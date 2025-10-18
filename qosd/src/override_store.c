#include "override_store.h"

#include <stdlib.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

#define MAX_OVERRIDES 256
#define DEFAULT_ALPHA 0.6

static struct persona_override overrides[MAX_OVERRIDES];

static struct persona_override *find_slot(const char *ip, int create)
{
    if (!ip || !*ip)
        return NULL;

    int free_idx = -1;
    for (size_t i = 0; i < ARRAY_SIZE(overrides); i++) {
        if (overrides[i].ip[0] && strcmp(overrides[i].ip, ip) == 0)
            return &overrides[i];
        if (free_idx < 0 && overrides[i].ip[0] == '\0')
            free_idx = (int)i;
    }
    if (create && free_idx >= 0) {
        memset(&overrides[free_idx], 0, sizeof(overrides[free_idx]));
        strncpy(overrides[free_idx].ip, ip, sizeof(overrides[free_idx].ip) - 1);
        overrides[free_idx].alpha = DEFAULT_ALPHA;
        overrides[free_idx].updates = 0;
        return &overrides[free_idx];
    }
    return NULL;
}

int override_store_apply(const char *ip, const struct persona_result *res,
                         double new_confidence, double alpha)
{
    struct persona_override *ov = find_slot(ip, 1);
    if (!ov)
        return -1;

    if (res) {
        if (res->persona[0])
            strncpy(ov->persona, res->persona, sizeof(ov->persona) - 1);
        ov->persona[sizeof(ov->persona) - 1] = '\0';
        if (res->priority[0])
            strncpy(ov->priority, res->priority, sizeof(ov->priority) - 1);
        ov->priority[sizeof(ov->priority) - 1] = '\0';
        if (res->policy_action[0])
            strncpy(ov->policy_action, res->policy_action, sizeof(ov->policy_action) - 1);
        ov->policy_action[sizeof(ov->policy_action) - 1] = '\0';
        if (res->dscp[0])
            strncpy(ov->dscp, res->dscp, sizeof(ov->dscp) - 1);
        ov->dscp[sizeof(ov->dscp) - 1] = '\0';
    }

    if (alpha > 0.0 && alpha < 1.0)
        ov->alpha = alpha;

    if (new_confidence >= 0.0) {
        if (ov->updates == 0)
            ov->confidence = new_confidence;
        else
            ov->confidence = ov->alpha * new_confidence + (1.0 - ov->alpha) * ov->confidence;
    }
    ov->updates++;
    return 0;
}

const struct persona_override *override_store_lookup(const char *ip)
{
    return find_slot(ip, 0);
}

void override_store_reset(void)
{
    memset(overrides, 0, sizeof(overrides));
}
