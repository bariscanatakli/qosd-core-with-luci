#include "classifier.h"
#include "config.h"
#include "dpi_signatures.h"
#include "override_store.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

struct persona_profile {
    const char *persona;
    const char *priority;
    const char *policy_action;
    const char *dscp;
    uint8_t confidence;
};

static void apply_profile(struct persona_result *res, const struct persona_profile *profile)
{
    if (!res || !profile)
        return;

    strncpy(res->persona, profile->persona, sizeof(res->persona) - 1);
    strncpy(res->priority, profile->priority, sizeof(res->priority) - 1);
    strncpy(res->policy_action, profile->policy_action, sizeof(res->policy_action) - 1);
    strncpy(res->dscp, profile->dscp, sizeof(res->dscp) - 1);

    res->persona[sizeof(res->persona) - 1] = '\0';
    res->priority[sizeof(res->priority) - 1] = '\0';
    res->policy_action[sizeof(res->policy_action) - 1] = '\0';
    res->dscp[sizeof(res->dscp) - 1] = '\0';
    res->confidence = profile->confidence;
}

static const struct qosd_config *g_config;

void classifier_set_config(const struct qosd_config *cfg)
{
    g_config = cfg;
}

static void apply_config_override(struct persona_result *res)
{
    if (!g_config || !res)
        return;

    const struct qosd_persona_policy *policy = qosd_config_find_persona(g_config, res->persona);
    if (!policy)
        return;

    if (policy->priority[0]) {
        strncpy(res->priority, policy->priority, sizeof(res->priority) - 1);
        res->priority[sizeof(res->priority) - 1] = '\0';
    }
    if (policy->policy_action[0]) {
        strncpy(res->policy_action, policy->policy_action, sizeof(res->policy_action) - 1);
        res->policy_action[sizeof(res->policy_action) - 1] = '\0';
    }
    if (policy->dscp[0]) {
        strncpy(res->dscp, policy->dscp, sizeof(res->dscp) - 1);
        res->dscp[sizeof(res->dscp) - 1] = '\0';
    }
    if (res->confidence < policy->min_confidence)
        res->confidence = policy->min_confidence;
}

static int strcasestr_match(const char *haystack, const char *needle)
{
    return (haystack && needle && *haystack && *needle && strcasestr(haystack, needle) != NULL);
}

static int streq_nocase(const char *a, const char *b)
{
    return (a && b) ? strcasecmp(a, b) == 0 : 0;
}

static int str_has_token(const char *haystack, const char *token)
{
    if (!haystack || !token || !*haystack || !*token)
        return 0;
    const char *pos = haystack;
    size_t tok_len = strlen(token);

    while ((pos = strcasestr(pos, token)) != NULL) {
        int prefix_ok = (pos == haystack) || pos[-1] == '.' || pos[-1] == '-' || pos[-1] == ' ';
        int suffix_ok = (pos[tok_len] == '\0') || pos[tok_len] == '.' || pos[tok_len] == '-' || pos[tok_len] == ' ';
        if (prefix_ok && suffix_ok)
            return 1;
        pos += tok_len;
    }
    return 0;
}

static uint16_t to_lower_port(uint16_t port)
{
    return port ? port : 0;
}

static int port_in_list(uint16_t port, const uint16_t *list, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == port)
            return 1;
    }
    return 0;
}

static void set_default_result(struct persona_result *res)
{
    struct persona_profile profile = {
        .persona = "other",
        .priority = "normal",
        .policy_action = "observe",
        .dscp = "CS0",
        .confidence = 20
    };
    apply_profile(res, &profile);
}

void classify_persona(const struct persona_request *req, struct persona_result *res)
{
    static const uint16_t streaming_ports[] = { 1935, 554, 1755, 8554, 8000, 8001, 8002, 9000 };
    static const uint16_t gaming_ports[] = { 3074, 3478, 3659, 3724, 6112, 27015, 27036, 50000 };
    static const uint16_t voip_ports[] = { 3478, 3479, 3480, 5004, 5060, 5061, 10000, 16384 };
    static const uint16_t work_ports[] = { 22, 53, 80, 443, 993, 3389, 5938 };
    static const uint16_t bulk_ports[] = { 20, 21, 80, 443, 445, 8080, 5001 };

    if (!res) {
        return;
    }

    set_default_result(res);

    if (!req) {
        apply_config_override(res);
        return;
    }

    const char *proto = req->proto ? req->proto : "";
    const char *hostname = req->hostname ? req->hostname : "";
    const char *service_hint = req->service_hint ? req->service_hint : "";
    const char *dns_name = req->dns_name ? req->dns_name : "";
    const char *app_hint = req->app_hint ? req->app_hint : "";
    uint16_t sport = to_lower_port(req->src_port);
    uint16_t dport = to_lower_port(req->dst_port);

    uint64_t total_bytes = req->bytes_total;
    uint32_t latency_ms = req->latency_ms;

    struct persona_profile profile = {
        .persona = res->persona,
        .priority = res->priority,
        .policy_action = res->policy_action,
        .dscp = res->dscp,
        .confidence = res->confidence
    };

    const char *sni = req->sni ? req->sni : "";
    const char *alpn = req->alpn ? req->alpn : "";
    const char *ja3 = req->ja3 ? req->ja3 : "";

    struct persona_result sig_res = {0};
    if (dpi_signature_match(req, &sig_res)) {
        struct persona_profile sig_profile = {
            .persona = sig_res.persona,
            .priority = sig_res.priority,
            .policy_action = sig_res.policy_action,
            .dscp = sig_res.dscp,
            .confidence = sig_res.confidence
        };
        apply_profile(res, &sig_profile);
        apply_config_override(res);
        return;
    }

    /* Highest confidence buckets first */
    if (strcasestr_match(service_hint, "zoom") ||
        strcasestr_match(service_hint, "meet") ||
        strcasestr_match(service_hint, "teams") ||
        strcasestr_match(sni, "zoom") ||
        strcasestr_match(sni, "webex") ||
        strcasestr_match(dns_name, "zoom.us") ||
        strcasestr_match(alpn, "zoom") ||
        port_in_list(dport, voip_ports, sizeof(voip_ports)/sizeof(voip_ports[0])) ||
        port_in_list(sport, voip_ports, sizeof(voip_ports)/sizeof(voip_ports[0]))) {

        profile = (struct persona_profile){
            .persona = "voip",
            .priority = "high",
            .policy_action = "boost",
            .dscp = "EF",
            .confidence = 90
        };
    } else if (str_has_token(ja3, "771,4865-4866-4867-4868-49195-49199")) {
        profile = (struct persona_profile){
            .persona = "voip",
            .priority = "high",
            .policy_action = "boost",
            .dscp = "EF",
            .confidence = 88
        };
    } else if (strcasestr_match(service_hint, "game") ||
               strcasestr_match(hostname, "ps5") ||
               strcasestr_match(hostname, "xbox") ||
               strcasestr_match(dns_name, "steam") ||
               strcasestr_match(sni, "playstation") ||
               strcasestr_match(sni, "xboxlive") ||
               strcasestr_match(sni, "riotgames") ||
               port_in_list(dport, gaming_ports, sizeof(gaming_ports)/sizeof(gaming_ports[0])) ||
               port_in_list(sport, gaming_ports, sizeof(gaming_ports)/sizeof(gaming_ports[0]))) {

        profile = (struct persona_profile){
            .persona = "gaming",
            .priority = "high",
            .policy_action = "boost",
            .dscp = "CS6",
            .confidence = 85
        };
    } else if (streq_nocase(alpn, "h3") && (strcasestr_match(sni, "youtube") || strcasestr_match(sni, "ytimg"))) {
        profile = (struct persona_profile){
            .persona = "streaming",
            .priority = "medium",
            .policy_action = "boost",
            .dscp = "AF41",
            .confidence = 82
        };
    } else if (strcasestr_match(service_hint, "youtube") ||
               strcasestr_match(service_hint, "netflix") ||
               strcasestr_match(service_hint, "prime") ||
               strcasestr_match(dns_name, "netflix") ||
               strcasestr_match(dns_name, "nflxvideo") ||
               strcasestr_match(sni, "netflix") ||
               strcasestr_match(sni, "hbomax") ||
               strcasestr_match(sni, "disneyplus") ||
               port_in_list(dport, streaming_ports, sizeof(streaming_ports)/sizeof(streaming_ports[0]))) {

        profile = (struct persona_profile){
            .persona = "streaming",
            .priority = "medium",
            .policy_action = "boost",
            .dscp = "AF41",
            .confidence = 75
        };
    } else if (strcasestr_match(service_hint, "work") ||
               strcasestr_match(service_hint, "vpn") ||
               strcasestr_match(dns_name, "microsoft.com") ||
               strcasestr_match(dns_name, "office365") ||
               strcasestr_match(sni, "teams.microsoft.com") ||
               strcasestr_match(sni, "zoomgov") ||
               port_in_list(dport, work_ports, sizeof(work_ports)/sizeof(work_ports[0]))) {

        profile = (struct persona_profile){
            .persona = "work",
            .priority = "medium",
            .policy_action = "boost",
            .dscp = "AF21",
            .confidence = 65
        };
    } else if (strcasestr_match(service_hint, "cam") ||
               strcasestr_match(hostname, "cam") ||
               strcasestr_match(hostname, "iot") ||
               strcasestr_match(dns_name, "tplinkcloud") ||
               strcasestr_match(dns_name, "homekit")) {

        profile = (struct persona_profile){
            .persona = "iot",
            .priority = "low",
            .policy_action = "observe",
            .dscp = "CS2",
            .confidence = 55
        };
    } else if (port_in_list(dport, bulk_ports, sizeof(bulk_ports)/sizeof(bulk_ports[0])) ||
               port_in_list(sport, bulk_ports, sizeof(bulk_ports)/sizeof(bulk_ports[0])) ||
               total_bytes > (300ULL * 1024ULL * 1024ULL)) {

        profile = (struct persona_profile){
            .persona = "bulk",
            .priority = "low",
            .policy_action = "throttle",
            .dscp = "CS1",
            .confidence = 60
        };
    } else if (!strcasecmp(proto, "udp")) {
        profile = (struct persona_profile){
            .persona = "latency",
            .priority = "medium",
            .policy_action = "boost",
            .dscp = "CS5",
            .confidence = 50
        };
    }

    /* Refine confidence with latency hints */
    if (latency_ms > 150 && profile.confidence < 95 &&
        (strcmp(profile.policy_action, "boost") == 0)) {
        profile.confidence = (uint8_t)((profile.confidence + 10) > 100 ? 100 : profile.confidence + 10);
    }

    if (strcasestr_match(app_hint, "critical")) {
        if (profile.confidence < 100)
            profile.confidence = (uint8_t)((profile.confidence + 15) > 100 ? 100 : profile.confidence + 15);
        profile.priority = "high";
        profile.policy_action = "boost";
    }

    if (profile.confidence < 95 && streq_nocase(alpn, "h2")) {
        profile.confidence += 5;
        if (profile.confidence > 100)
            profile.confidence = 100;
    }

    const struct persona_override *ov_src = override_store_lookup(req->src_ip);
    const struct persona_override *ov_dst = override_store_lookup(req->dst_ip);
    const struct persona_override *ov = NULL;
    if (ov_src && ov_src->persona[0])
        ov = ov_src;
    if (ov_dst && ov_dst->persona[0]) {
        if (!ov || ov_dst->confidence > ov->confidence)
            ov = ov_dst;
    }

    if (ov && ov->confidence >= profile.confidence) {
        struct persona_profile override_profile = {
            .persona = ov->persona,
            .priority = ov->priority[0] ? ov->priority : profile.priority,
            .policy_action = ov->policy_action[0] ? ov->policy_action : profile.policy_action,
            .dscp = ov->dscp[0] ? ov->dscp : profile.dscp,
            .confidence = (uint8_t)(ov->confidence > 100.0 ? 100 : (ov->confidence < 0 ? 0 : ov->confidence))
        };
        profile = override_profile;
    }

    apply_profile(res, &profile);
    apply_config_override(res);
}
