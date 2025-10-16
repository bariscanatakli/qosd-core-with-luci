#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <syslog.h>
#include <inttypes.h>

#include "classifier.h"

#define MAX_HOSTS 1024
#define LEASES_FILE "/tmp/dhcp.leases"
#define ARP_FILE    "/proc/net/arp"
#define NFCT_FILE   "/proc/net/nf_conntrack"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

struct host_stat {
    char ip[64];
    char mac[32];
    char hostname[64];
    char persona[32];
    char priority[16];
    char policy_action[32];
    char dscp[16];
    uint8_t confidence;

    uint64_t cur_rx_bytes;
    uint64_t cur_tx_bytes;

    uint64_t prev_rx_bytes;
    uint64_t prev_tx_bytes;

    uint64_t rx_bps;
    uint64_t tx_bps;

    time_t last_seen;
    bool used;
};

static struct host_stat g_hosts[MAX_HOSTS];
static time_t g_prev_tick = 0;

static void iso8601_from_time(time_t ts, char *buf, size_t len)
{
    if (ts <= 0)
        ts = time(NULL);
    struct tm tm;
    if (!gmtime_r(&ts, &tm))
        memset(&tm, 0, sizeof(tm));
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static const char *router_id(void)
{
    static char cached[64] = {0};
    static int initialized = 0;
    if (!initialized) {
        if (gethostname(cached, sizeof(cached)) != 0 || cached[0] == '\0')
            strncpy(cached, "openwrt", sizeof(cached) - 1);
        cached[sizeof(cached) - 1] = '\0';
        initialized = 1;
    }
    return cached;
}

static void json_escape(const char *in, char *out, size_t out_len)
{
    size_t oi = 0;
    for (size_t i = 0; in && in[i] && oi + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (oi + 2 >= out_len)
                break;
            out[oi++] = '\\';
            out[oi++] = c;
        } else if (c <= 0x1F) {
            if (oi + 6 >= out_len)
                break;
            int written = snprintf(out + oi, out_len - oi, "\\u%04x", c);
            if (written < 0)
                break;
            oi += (size_t)written;
        } else {
            out[oi++] = c;
        }
    }
    out[oi] = '\0';
}

static inline int find_host_idx(const char *ip, bool create)
{
    int free_idx = -1;
    for (int i = 0; i < (int)ARRAY_SIZE(g_hosts); i++) {
        if (g_hosts[i].used && strcmp(g_hosts[i].ip, ip) == 0)
            return i;
        if (!g_hosts[i].used && free_idx < 0)
            free_idx = i;
    }
    if (create && free_idx >= 0) {
        memset(&g_hosts[free_idx], 0, sizeof(g_hosts[free_idx]));
        strncpy(g_hosts[free_idx].ip, ip, sizeof(g_hosts[free_idx].ip) - 1);
        g_hosts[free_idx].used = true;
        return free_idx;
    }
    return -1;
}

static void load_leases(void)
{
    FILE *f = fopen(LEASES_FILE, "r");
    if (!f)
        return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char ts[64], mac[64], ip[64], host[128], id[64];
        if (sscanf(line, "%63s %63s %63s %127s %63s", ts, mac, ip, host, id) >= 4) {
            int idx = find_host_idx(ip, true);
            if (idx >= 0) {
                if (strcmp(host, "*") != 0)
                    strncpy(g_hosts[idx].hostname, host, sizeof(g_hosts[idx].hostname) - 1);
                strncpy(g_hosts[idx].mac, mac, sizeof(g_hosts[idx].mac) - 1);
            }
        }
    }
    fclose(f);
}

static void load_arp(void)
{
    FILE *f = fopen(ARP_FILE, "r");
    if (!f)
        return;

    char line[512];
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char ip[64], hwaddr[64], junk1[64], junk2[64], junk3[64], junk4[64];
        if (sscanf(line, "%63s %63s %63s %63s %63s %63s", ip, junk1, junk2, hwaddr, junk3, junk4) == 6) {
            int idx = find_host_idx(ip, true);
            if (idx >= 0 && g_hosts[idx].mac[0] == '\0')
                strncpy(g_hosts[idx].mac, hwaddr, sizeof(g_hosts[idx].mac) - 1);
        }
    }
    fclose(f);
}

static void reset_current_counters(void)
{
    for (int i = 0; i < (int)ARRAY_SIZE(g_hosts); i++) {
        if (!g_hosts[i].used)
            continue;
        g_hosts[i].cur_rx_bytes = 0;
        g_hosts[i].cur_tx_bytes = 0;
        g_hosts[i].persona[0] = '\0';
        g_hosts[i].priority[0] = '\0';
        g_hosts[i].policy_action[0] = '\0';
        g_hosts[i].dscp[0] = '\0';
        g_hosts[i].confidence = 0;
    }
}

static void sample_nfconntrack(void)
{
    FILE *f = fopen(NFCT_FILE, "r");
    if (!f)
        return;

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char src[64] = {0}, dst[64] = {0};
        char proto[16] = {0};
        uint64_t orig_bytes = 0, reply_bytes = 0;
        uint16_t sport = 0, dport = 0;

        sscanf(line, "%*s %*s %15s", proto);

        char *s1 = strstr(p, "src=");
        char *d1 = strstr(p, "dst=");
        if (!s1 || !d1)
            continue;

        sscanf(s1, "src=%63s", src);
        sscanf(d1, "dst=%63s", dst);

        char *sp = strstr(p, "sport=");
        if (sp)
            sport = (uint16_t)strtoul(sp + 6, NULL, 10);

        char *dp = strstr(p, "dport=");
        if (dp)
            dport = (uint16_t)strtoul(dp + 6, NULL, 10);

        char *b1 = strstr(p, " bytes=");
        if (b1) {
            b1 += 7;
            orig_bytes = strtoull(b1, NULL, 10);
            char *b2 = strstr(b1, " bytes=");
            if (b2) {
                b2 += 7;
                reply_bytes = strtoull(b2, NULL, 10);
            }
        }

        if (src[0]) {
            int is = find_host_idx(src, true);
            if (is >= 0) {
                struct host_stat *h = &g_hosts[is];
                h->cur_tx_bytes += orig_bytes;
                h->last_seen = time(NULL);

                struct persona_request req = {
                    .proto = proto,
                    .src_port = sport,
                    .dst_port = dport,
                    .hostname = h->hostname[0] ? h->hostname : NULL,
                    .bytes_total = orig_bytes + reply_bytes,
                };
                struct persona_result res = {0};
                classify_persona(&req, &res);
                if (res.confidence >= h->confidence) {
                    strncpy(h->persona, res.persona, sizeof(h->persona) - 1);
                    strncpy(h->priority, res.priority, sizeof(h->priority) - 1);
                    strncpy(h->policy_action, res.policy_action, sizeof(h->policy_action) - 1);
                    strncpy(h->dscp, res.dscp, sizeof(h->dscp) - 1);
                    h->persona[sizeof(h->persona) - 1] = '\0';
                    h->priority[sizeof(h->priority) - 1] = '\0';
                    h->policy_action[sizeof(h->policy_action) - 1] = '\0';
                    h->dscp[sizeof(h->dscp) - 1] = '\0';
                    h->confidence = res.confidence;
                }
            }
        }
        if (dst[0]) {
            int id = find_host_idx(dst, true);
            if (id >= 0) {
                struct host_stat *h = &g_hosts[id];
                h->cur_rx_bytes += reply_bytes;
                h->last_seen = time(NULL);

                struct persona_request req = {
                    .proto = proto,
                    .src_port = sport,
                    .dst_port = dport,
                    .hostname = h->hostname[0] ? h->hostname : NULL,
                    .bytes_total = orig_bytes + reply_bytes,
                };
                struct persona_result res = {0};
                classify_persona(&req, &res);
                if (res.confidence >= h->confidence) {
                    strncpy(h->persona, res.persona, sizeof(h->persona) - 1);
                    strncpy(h->priority, res.priority, sizeof(h->priority) - 1);
                    strncpy(h->policy_action, res.policy_action, sizeof(h->policy_action) - 1);
                    strncpy(h->dscp, res.dscp, sizeof(h->dscp) - 1);
                    h->persona[sizeof(h->persona) - 1] = '\0';
                    h->priority[sizeof(h->priority) - 1] = '\0';
                    h->policy_action[sizeof(h->policy_action) - 1] = '\0';
                    h->dscp[sizeof(h->dscp) - 1] = '\0';
                    h->confidence = res.confidence;
                }
            }
        }
    }
    fclose(f);
}

static int cmp_bps_desc(const void *a, const void *b)
{
    const struct host_stat *ha = *(const struct host_stat *const *)a;
    const struct host_stat *hb = *(const struct host_stat *const *)b;
    uint64_t aa = ha->rx_bps + ha->tx_bps;
    uint64_t bb = hb->rx_bps + hb->tx_bps;
    return (aa < bb) ? 1 : (aa > bb ? -1 : 0);
}

static void compute_bps_and_sort(unsigned limit, struct host_stat **out_list, unsigned *out_n)
{
    time_t now = time(NULL);
    double dt = difftime(now, g_prev_tick);
    if (dt <= 0.0)
        dt = 1.0;

    unsigned n = 0;
    for (int i = 0; i < (int)ARRAY_SIZE(g_hosts); i++) {
        if (!g_hosts[i].used)
            continue;

        uint64_t d_rx = 0, d_tx = 0;

        if (g_hosts[i].cur_rx_bytes >= g_hosts[i].prev_rx_bytes)
            d_rx = g_hosts[i].cur_rx_bytes - g_hosts[i].prev_rx_bytes;
        if (g_hosts[i].cur_tx_bytes >= g_hosts[i].prev_tx_bytes)
            d_tx = g_hosts[i].cur_tx_bytes - g_hosts[i].prev_tx_bytes;

        g_hosts[i].rx_bps = (uint64_t)((double)d_rx * 8.0 / dt);
        g_hosts[i].tx_bps = (uint64_t)((double)d_tx * 8.0 / dt);

        g_hosts[i].prev_rx_bytes = g_hosts[i].cur_rx_bytes;
        g_hosts[i].prev_tx_bytes = g_hosts[i].cur_tx_bytes;

        out_list[n++] = &g_hosts[i];
        if (n >= ARRAY_SIZE(g_hosts))
            break;
    }

    qsort(out_list, n, sizeof(out_list[0]), cmp_bps_desc);

    if (limit && n > limit)
        n = limit;
    *out_n = n;
    g_prev_tick = now;
}

static void refresh_snapshot(void)
{
    reset_current_counters();
    load_leases();
    load_arp();
    sample_nfconntrack();
}

static void log_live_snapshot(const struct host_stat *h)
{
    if (!h || !h->used)
        return;

    char ts_now[32];
    iso8601_from_time(time(NULL), ts_now, sizeof(ts_now));

    char ts_seen[32] = "";
    if (h->last_seen)
        iso8601_from_time(h->last_seen, ts_seen, sizeof(ts_seen));

    const char *hostname = h->hostname[0] ? h->hostname : "";
    const char *ip = h->ip[0] ? h->ip : "";
    const char *mac = h->mac[0] ? h->mac : "";
    const char *persona = h->persona[0] ? h->persona : "";
    const char *priority = h->priority[0] ? h->priority : "";
    const char *policy = h->policy_action[0] ? h->policy_action : "";
    const char *dscp = h->dscp[0] ? h->dscp : "";
    const char *router = router_id();

    char host_esc[128];
    char ip_esc[80];
    char mac_esc[48];
    char persona_esc[48];
    char pri_esc[48];
    char policy_esc[48];
    char dscp_esc[32];
    char router_esc[64];
    char seen_esc[40];

    json_escape(hostname, host_esc, sizeof(host_esc));
    json_escape(ip, ip_esc, sizeof(ip_esc));
    json_escape(mac, mac_esc, sizeof(mac_esc));
    json_escape(persona, persona_esc, sizeof(persona_esc));
    json_escape(priority, pri_esc, sizeof(pri_esc));
    json_escape(policy, policy_esc, sizeof(policy_esc));
    json_escape(dscp, dscp_esc, sizeof(dscp_esc));
    json_escape(router, router_esc, sizeof(router_esc));
    json_escape(ts_seen, seen_esc, sizeof(seen_esc));

    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"event\":\"qosd_live\",\"timestamp\":\"%s\",\"hostname\":\"%s\","
             "\"ip\":\"%s\",\"mac\":\"%s\",\"persona\":\"%s\",\"priority\":\"%s\","
             "\"policy_action\":\"%s\",\"dscp\":\"%s\",\"confidence\":%u,"
             "\"rx_bps\":%" PRIu64 ",\"tx_bps\":%" PRIu64 ",\"last_seen\":\"%s\","
             "\"router\":\"%s\"}",
             ts_now, host_esc, ip_esc, mac_esc, persona_esc, pri_esc,
             policy_esc, dscp_esc, h->confidence,
             h->rx_bps, h->tx_bps, seen_esc, router_esc);
    syslog(LOG_INFO, "%s", payload);
}

static const struct blobmsg_policy live_policy[] = {
    { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
};

int qosd_live_handler(struct ubus_context *ctx, struct ubus_object *obj,
                      struct ubus_request_data *req, const char *method,
                      struct blob_attr *msg)
{
    (void)obj;
    (void)method;

    int limit = 50;
    struct blob_attr *tb[ARRAY_SIZE(live_policy)];

    blobmsg_parse(live_policy, ARRAY_SIZE(live_policy), tb, blob_data(msg), blob_len(msg));
    if (tb[0])
        limit = blobmsg_get_u32(tb[0]);

    refresh_snapshot();

    struct host_stat *list[MAX_HOSTS];
    unsigned n = 0;
    compute_bps_and_sort(limit, list, &n);

    static struct blob_buf b;
    blob_buf_init(&b, 0);
    void *arr = blobmsg_open_array(&b, "hosts");

    for (unsigned i = 0; i < n; i++) {
        struct host_stat *h = list[i];
        void *t = blobmsg_open_table(&b, NULL);
        blobmsg_add_string(&b, "ip", h->ip[0] ? h->ip : "");
        blobmsg_add_string(&b, "mac", h->mac[0] ? h->mac : "");
        blobmsg_add_string(&b, "hostname", h->hostname[0] ? h->hostname : "");
        blobmsg_add_string(&b, "persona", h->persona[0] ? h->persona : "");
        blobmsg_add_string(&b, "category", h->persona[0] ? h->persona : "");
        blobmsg_add_string(&b, "priority", h->priority[0] ? h->priority : "");
        blobmsg_add_string(&b, "policy_action", h->policy_action[0] ? h->policy_action : "");
        blobmsg_add_string(&b, "dscp", h->dscp[0] ? h->dscp : "");
        blobmsg_add_u64(&b, "rx_bps", h->rx_bps);
        blobmsg_add_u64(&b, "tx_bps", h->tx_bps);
        blobmsg_add_u32(&b, "last_seen", (uint32_t)h->last_seen);
        blobmsg_add_u32(&b, "confidence", h->confidence);
        blobmsg_close_table(&b, t);

        log_live_snapshot(h);
    }

    blobmsg_close_array(&b, arr);
    return ubus_send_reply(ctx, req, b.head);
}

void qosd_live_method_init(struct ubus_method *method)
{
    *method = (struct ubus_method)UBUS_METHOD("live", qosd_live_handler, live_policy);
}
