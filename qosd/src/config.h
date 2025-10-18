#pragma once

#include <stddef.h>
#include <stdint.h>

#define QOSD_MAX_PERSONAS 16

struct qosd_persona_policy {
    char name[32];
    char priority[16];
    char policy_action[32];
    char dscp[16];
    uint8_t min_confidence;
};

struct qosd_config {
    struct qosd_persona_policy personas[QOSD_MAX_PERSONAS];
    size_t persona_count;
    uint32_t watchdog_backoff_ms;
};

int qosd_config_load(struct qosd_config *cfg, const char *config_name);
const struct qosd_persona_policy *qosd_config_find_persona(const struct qosd_config *cfg, const char *persona);
