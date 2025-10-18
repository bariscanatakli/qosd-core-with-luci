#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uci.h>

/* Schema follows Dong et al. (IEEE Access 2019) persona-aware QoS templates:
 * each persona maps to priority/DSPC/action pairs enforced at runtime. */

static void trim_lower(char *dst, size_t dst_len, const char *src)
{
    if (!dst || !dst_len)
        return;
    size_t i;
    for (i = 0; i + 1 < dst_len && src && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static void to_upper(char *s)
{
    if (!s)
        return;
    for (; *s; s++)
        *s = (char)toupper((unsigned char)*s);
}

static int validate_priority(const char *priority)
{
    static const char *valid[] = { "high", "medium", "low", "bulk", "normal" };
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) {
        if (strcmp(priority, valid[i]) == 0)
            return 0;
    }
    return -1;
}

static int validate_policy(const char *action)
{
    static const char *valid[] = { "boost", "throttle", "observe" };
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) {
        if (strcmp(action, valid[i]) == 0)
            return 0;
    }
    return -1;
}

static int validate_dscp(const char *dscp)
{
    if (!dscp || !*dscp)
        return -1;
    /* Accept CSx, AFxy, or EF per CAKE (Morton & Hoeiland-Joergensen 2023). */
    if (!strncmp(dscp, "cs", 2) && strlen(dscp) == 3 && isdigit((unsigned char)dscp[2]))
        return 0;
    if (!strncmp(dscp, "af", 2) && strlen(dscp) == 4 &&
        isdigit((unsigned char)dscp[2]) && isdigit((unsigned char)dscp[3]))
        return 0;
    if (strcmp(dscp, "ef") == 0)
        return 0;
    return -1;
}

static void persona_policy_reset(struct qosd_persona_policy *p)
{
    if (!p)
        return;
    memset(p, 0, sizeof(*p));
    p->min_confidence = 0;
}

static int load_persona(struct qosd_config *cfg, struct uci_section *section)
{
    if (!cfg || !section)
        return -1;
    if (cfg->persona_count >= QOSD_MAX_PERSONAS)
        return -1;

    struct qosd_persona_policy *persona = &cfg->personas[cfg->persona_count];
    persona_policy_reset(persona);

    const char *name = section->e.name;
    if (!name || !*name)
        return -1;

    /* ensure uniqueness */
    for (size_t i = 0; i < cfg->persona_count; i++) {
        if (strcmp(cfg->personas[i].name, name) == 0)
            return -1;
    }

    strncpy(persona->name, name, sizeof(persona->name) - 1);
    persona->name[sizeof(persona->name) - 1] = '\0';

    const char *priority = uci_lookup_option_string(section->package->ctx, section, "priority");
    const char *policy = uci_lookup_option_string(section->package->ctx, section, "policy_action");
    const char *dscp = uci_lookup_option_string(section->package->ctx, section, "dscp");
    const char *confidence = uci_lookup_option_string(section->package->ctx, section, "min_confidence");

    char tmp_priority[16] = "";
    char tmp_policy[16] = "";
    char tmp_dscp[16] = "";

    if (priority)
        trim_lower(tmp_priority, sizeof(tmp_priority), priority);
    if (policy)
        trim_lower(tmp_policy, sizeof(tmp_policy), policy);
    if (dscp)
        trim_lower(tmp_dscp, sizeof(tmp_dscp), dscp);

    if (!*tmp_priority || validate_priority(tmp_priority) != 0)
        strncpy(tmp_priority, "normal", sizeof(tmp_priority) - 1);
    if (!*tmp_policy || validate_policy(tmp_policy) != 0)
        strncpy(tmp_policy, "observe", sizeof(tmp_policy) - 1);
    if (!*tmp_dscp || validate_dscp(tmp_dscp) != 0)
        strncpy(tmp_dscp, "cs0", sizeof(tmp_dscp) - 1);

    strncpy(persona->priority, tmp_priority, sizeof(persona->priority) - 1);
    persona->priority[sizeof(persona->priority) - 1] = '\0';

    strncpy(persona->policy_action, tmp_policy, sizeof(persona->policy_action) - 1);
    persona->policy_action[sizeof(persona->policy_action) - 1] = '\0';

    strncpy(persona->dscp, tmp_dscp, sizeof(persona->dscp) - 1);
    persona->dscp[sizeof(persona->dscp) - 1] = '\0';
    to_upper(persona->dscp);

    if (confidence && *confidence)
        persona->min_confidence = (uint8_t)strtoul(confidence, NULL, 10);
    cfg->persona_count++;
    return 0;
}

int qosd_config_load(struct qosd_config *cfg, const char *config_name)
{
    if (!cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    struct uci_context *uci = uci_alloc_context();
    if (!uci)
        return -1;

    struct uci_package *pkg = NULL;
    int err = uci_load(uci, config_name ? config_name : "qosd", &pkg);
    if (err != UCI_OK) {
        uci_free_context(uci);
        return -1;
    }

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!s)
            continue;
        if (strcmp(s->type, "persona") == 0) {
            if (load_persona(cfg, s) != 0) {
                /* skip invalid persona but continue to align with Feamster 2017 resilience guidance */
                continue;
            }
        } else if (strcmp(s->type, "watchdog") == 0) {
            const char *backoff = uci_lookup_option_string(uci, s, "backoff_ms");
            if (backoff && *backoff)
                cfg->watchdog_backoff_ms = (uint32_t)strtoul(backoff, NULL, 10);
        }
    }

    uci_unload(uci, pkg);
    uci_free_context(uci);

    return (int)cfg->persona_count;
}

const struct qosd_persona_policy *
qosd_config_find_persona(const struct qosd_config *cfg, const char *persona)
{
    if (!cfg || !persona || !*persona)
        return NULL;
    for (size_t i = 0; i < cfg->persona_count; i++) {
        if (strcmp(cfg->personas[i].name, persona) == 0)
            return &cfg->personas[i];
    }
    return NULL;
}
