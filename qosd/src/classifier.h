#pragma once

#include <stdint.h>

struct persona_request {
    const char *proto;       /* "tcp", "udp", etc. */
    uint16_t src_port;
    uint16_t dst_port;
    const char *src_ip;      /* Source IP address */
    const char *dst_ip;      /* Destination IP address */
    const char *hostname;    /* DHCP lease hostname if available */
    const char *service_hint;/* App/service hint (e.g. "netflix", "zoom") */
    const char *dns_name;    /* Resolved domain if available */
    const char *app_hint;    /* Additional hint from caller */
    const char *sni;         /* TLS SNI if observed */
    const char *alpn;        /* ALPN/QUIC negotiated protocol */
    const char *ja3;         /* JA3 fingerprint string */
    uint64_t bytes_total;    /* Observed bytes on flow */
    uint32_t latency_ms;     /* Observed latency */
};

struct persona_result {
    char persona[32];        /* streaming/gaming/voip/bulk/work/iot/other */
    char priority[16];       /* high/medium/low/bulk */
    char policy_action[32];  /* boost/throttle/observe */
    char dscp[16];           /* e.g. EF/AF41/CS1 */
    uint8_t confidence;      /* 0-100 confidence score */
};

struct qosd_config;

void classifier_set_config(const struct qosd_config *cfg);
void classify_persona(const struct persona_request *req, struct persona_result *res);
