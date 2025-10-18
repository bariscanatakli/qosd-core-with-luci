#pragma once

#include <stddef.h>

#include "classifier.h"

struct persona_override {
    char ip[64];
    char persona[32];
    char priority[16];
    char policy_action[32];
    char dscp[16];
    double confidence;
    double alpha;
    unsigned int updates;
};

int override_store_apply(const char *ip, const struct persona_result *res,
                         double new_confidence, double alpha);
const struct persona_override *override_store_lookup(const char *ip);
void override_store_reset(void);
