#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <syslog.h>
#include <time.h>
#include <strings.h>
#include <string.h>

#include "classifier.h"

static struct ubus_context *ctx;
static struct blob_buf bb;

void qosd_live_method_init(struct ubus_method *method);

enum {
    CL_SRC,
    CL_DST,
    CL_PROTO,
    CL_SRC_PORT,
    CL_DST_PORT,
    CL_HOSTNAME,
    CL_SERVICE,
    CL_DNS,
    CL_APP,
    CL_BYTES,
    CL_LATENCY,
    __CL_MAX
};

static const struct blobmsg_policy classify_policy[__CL_MAX] = {
    [CL_SRC]   = { .name = "src",   .type = BLOBMSG_TYPE_STRING },
    [CL_DST]   = { .name = "dst",   .type = BLOBMSG_TYPE_STRING },
    [CL_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
    [CL_SRC_PORT] = { .name = "src_port", .type = BLOBMSG_TYPE_INT32 },
    [CL_DST_PORT] = { .name = "dst_port", .type = BLOBMSG_TYPE_INT32 },
    [CL_HOSTNAME] = { .name = "hostname", .type = BLOBMSG_TYPE_STRING },
    [CL_SERVICE]  = { .name = "service_hint", .type = BLOBMSG_TYPE_STRING },
    [CL_DNS]      = { .name = "dns_name", .type = BLOBMSG_TYPE_STRING },
    [CL_APP]      = { .name = "app_hint", .type = BLOBMSG_TYPE_STRING },
    [CL_BYTES]    = { .name = "bytes_total", .type = BLOBMSG_TYPE_INT64 },
    [CL_LATENCY]  = { .name = "latency_ms", .type = BLOBMSG_TYPE_INT32 },
};

static void iso8601_now(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm;
    if (!gmtime_r(&now, &tm))
        memset(&tm, 0, sizeof(tm));
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
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

static int
qosd_classify(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *ureq, const char *method,
              struct blob_attr *msg)
{
    struct blob_attr *tb[__CL_MAX];
    blobmsg_parse(classify_policy, __CL_MAX, tb, blob_data(msg), blob_len(msg));

    const char *src   = tb[CL_SRC]   ? blobmsg_get_string(tb[CL_SRC])   : "unknown";
    const char *dst   = tb[CL_DST]   ? blobmsg_get_string(tb[CL_DST])   : "unknown";
    const char *proto = tb[CL_PROTO] ? blobmsg_get_string(tb[CL_PROTO]) : "unknown";
    uint16_t src_port = tb[CL_SRC_PORT] ? (uint16_t)blobmsg_get_u32(tb[CL_SRC_PORT]) : 0;
    uint16_t dst_port = tb[CL_DST_PORT] ? (uint16_t)blobmsg_get_u32(tb[CL_DST_PORT]) : 0;
    const char *hostname = tb[CL_HOSTNAME] ? blobmsg_get_string(tb[CL_HOSTNAME]) : "";
    const char *service_hint = tb[CL_SERVICE] ? blobmsg_get_string(tb[CL_SERVICE]) : "";
    const char *dns_name = tb[CL_DNS] ? blobmsg_get_string(tb[CL_DNS]) : "";
    const char *app_hint = tb[CL_APP] ? blobmsg_get_string(tb[CL_APP]) : "";
    uint64_t bytes_total = tb[CL_BYTES] ? blobmsg_get_u64(tb[CL_BYTES]) : 0;
    uint32_t latency_ms = tb[CL_LATENCY] ? blobmsg_get_u32(tb[CL_LATENCY]) : 0;

    char persona_buf[32];
    char priority_buf[16];
    char policy_buf[32];
    char dscp_buf[16];
    struct persona_request preq = {
        .proto = proto,
        .src_port = src_port,
        .dst_port = dst_port,
        .hostname = hostname,
        .service_hint = service_hint,
        .dns_name = dns_name,
        .app_hint = app_hint,
        .bytes_total = bytes_total,
        .latency_ms = latency_ms,
    };

    struct persona_result pres = {0};
    classify_persona(&preq, &pres);

    strncpy(persona_buf, pres.persona, sizeof(persona_buf) - 1);
    persona_buf[sizeof(persona_buf) - 1] = '\0';
    strncpy(priority_buf, pres.priority, sizeof(priority_buf) - 1);
    priority_buf[sizeof(priority_buf) - 1] = '\0';
    strncpy(policy_buf, pres.policy_action, sizeof(policy_buf) - 1);
    policy_buf[sizeof(policy_buf) - 1] = '\0';
    strncpy(dscp_buf, pres.dscp, sizeof(dscp_buf) - 1);
    dscp_buf[sizeof(dscp_buf) - 1] = '\0';

    fprintf(stdout, "[qosd] classify: %s -> %s (%s)\n", src, dst, proto);

    blob_buf_init(&bb, 0);
    void *t = blobmsg_open_table(&bb, NULL);
    blobmsg_add_string(&bb, "persona", persona_buf);
    blobmsg_add_string(&bb, "category", persona_buf);
    blobmsg_add_string(&bb, "priority", priority_buf);
    blobmsg_add_string(&bb, "policy_action", policy_buf);
    blobmsg_add_string(&bb, "dscp", dscp_buf);
    blobmsg_add_u32(&bb, "confidence", pres.confidence);
    blobmsg_close_table(&bb, t);

    char ts[32];
    iso8601_now(ts, sizeof(ts));

    char src_esc[128];
    char dst_esc[128];
    char proto_esc[32];
    char category_esc[32];
    char priority_esc[32];
    char router_esc[64];
    char hostname_esc[128];
    char service_esc[128];
    char dns_esc[128];
    char policy_esc[64];
    char dscp_esc[32];
    char app_esc[128];

    json_escape(src, src_esc, sizeof(src_esc));
    json_escape(dst, dst_esc, sizeof(dst_esc));
    json_escape(proto, proto_esc, sizeof(proto_esc));
    json_escape(persona_buf, category_esc, sizeof(category_esc));
    json_escape(priority_buf, priority_esc, sizeof(priority_esc));
    json_escape(router_id(), router_esc, sizeof(router_esc));
    json_escape(hostname, hostname_esc, sizeof(hostname_esc));
    json_escape(service_hint, service_esc, sizeof(service_esc));
    json_escape(dns_name, dns_esc, sizeof(dns_esc));
    json_escape(policy_buf, policy_esc, sizeof(policy_esc));
    json_escape(dscp_buf, dscp_esc, sizeof(dscp_esc));
    json_escape(app_hint, app_esc, sizeof(app_esc));

    char payload[768];
    snprintf(payload, sizeof(payload),
             "{\"event\":\"qosd_classify\",\"timestamp\":\"%s\",\"src\":\"%s\","
             "\"dst\":\"%s\",\"proto\":\"%s\",\"category\":\"%s\",\"priority\":\"%s\","
             "\"router\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"hostname\":\"%s\","
             "\"service_hint\":\"%s\",\"dns_name\":\"%s\",\"policy_action\":\"%s\","
             "\"dscp\":\"%s\",\"confidence\":%u,\"bytes_total\":%llu,\"latency_ms\":%u,"
             "\"app_hint\":\"%s\"}",
             ts, src_esc, dst_esc, proto_esc, category_esc, priority_esc,
             router_esc, src_port, dst_port, hostname_esc, service_esc, dns_esc,
             policy_esc, dscp_esc, pres.confidence,
             (unsigned long long)bytes_total, latency_ms, app_esc);
    syslog(LOG_INFO, "%s", payload);

    ubus_send_reply(ctx, ureq, bb.head);
    return 0;
}

static struct ubus_method qosd_methods[2];

static void
qosd_methods_init(void)
{
    qosd_methods[0] = (struct ubus_method)UBUS_METHOD("classify", qosd_classify, classify_policy);
    qosd_live_method_init(&qosd_methods[1]);
}

static struct ubus_object_type qosd_obj_type =
    UBUS_OBJECT_TYPE("qosd", qosd_methods);

static struct ubus_object qosd_obj = {
    .name = "qosd",
    .type = &qosd_obj_type,
    .methods = qosd_methods,
    .n_methods = ARRAY_SIZE(qosd_methods),
};

int main(int argc, char **argv)
{
    uloop_init();
    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return 1;
    }

    ubus_add_uloop(ctx);

    openlog("qosd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    qosd_methods_init();

    int ret = ubus_add_object(ctx, &qosd_obj);
    if (ret) {
        fprintf(stderr, "ubus_add_object failed: %d\n", ret);
        return 1;
    }

    printf("QoSD registered to ubus successfully!\n");
    uloop_run();

    ubus_free(ctx);
    uloop_done();
    return 0;
}
