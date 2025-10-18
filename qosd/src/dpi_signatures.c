#include "dpi_signatures.h"

#include <string.h>
#include <strings.h>

/* Lightweight signature pack inspired by nDPI/Netify heuristics and
 * Dong et al. (IEEE Access 2019) context-aware persona templates. */

enum match_field {
    MATCH_SNI,
    MATCH_DNS,
    MATCH_JA3,
    MATCH_SERVICE,
    MATCH_APP_HINT,
};

struct signature_rule {
    enum match_field field;
    const char *pattern;
    const char *persona;
    const char *priority;
    const char *policy_action;
    const char *dscp;
    uint8_t confidence;
};

static const struct signature_rule signature_table[] = {
    { MATCH_SNI,      "zoom.us",          "voip",      "high",   "boost",    "EF",   92 },
    { MATCH_SNI,      "teams.microsoft",  "voip",      "high",   "boost",    "EF",   90 },
    { MATCH_SNI,      "meet.google",      "voip",      "high",   "boost",    "EF",   88 },
    { MATCH_JA3,      "769,49195-49199",  "voip",      "high",   "boost",    "EF",   86 },
    { MATCH_SNI,      "netflix.com",      "streaming", "medium", "boost",    "AF41", 82 },
    { MATCH_SNI,      "disneyplus",       "streaming", "medium", "boost",    "AF41", 80 },
    { MATCH_SNI,      "youtube",          "streaming", "medium", "boost",    "AF41", 83 },
    { MATCH_SERVICE,  "twitch",           "streaming", "medium", "boost",    "AF41", 81 },
    { MATCH_SNI,      "psn",              "gaming",    "high",   "boost",    "CS6",  86 },
    { MATCH_SNI,      "xboxlive",         "gaming",    "high",   "boost",    "CS6",  86 },
    { MATCH_APP_HINT, "fortnite",         "gaming",    "high",   "boost",    "CS6",  87 },
    { MATCH_SNI,      "riotgames",        "gaming",    "high",   "boost",    "CS6",  85 },
    { MATCH_SNI,      "workplace.com",    "work",      "medium", "boost",    "AF21", 75 },
    { MATCH_SERVICE,  "office365",        "work",      "medium", "boost",    "AF21", 74 },
    { MATCH_SERVICE,  "vpn",              "work",      "medium", "boost",    "AF21", 76 },
    { MATCH_SNI,      "nest.com",         "iot",       "low",    "observe",  "CS2",  60 },
    { MATCH_SNI,      "tplinkcloud",      "iot",       "low",    "observe",  "CS2",  60 },
    { MATCH_SNI,      "update.apple",     "bulk",      "low",    "throttle", "CS1",  62 },
    { MATCH_SERVICE,  "backup",           "bulk",      "low",    "throttle", "CS1",  65 },
};

static int field_matches(enum match_field field, const struct persona_request *req, const char *pattern)
{
    if (!req || !pattern)
        return 0;

    switch (field) {
    case MATCH_SNI:
        return req->sni && strcasestr(req->sni, pattern);
    case MATCH_DNS:
        return req->dns_name && strcasestr(req->dns_name, pattern);
    case MATCH_JA3:
        return req->ja3 && strcasestr(req->ja3, pattern);
    case MATCH_SERVICE:
        return req->service_hint && strcasestr(req->service_hint, pattern);
    case MATCH_APP_HINT:
        return req->app_hint && strcasestr(req->app_hint, pattern);
    default:
        return 0;
    }
}

int dpi_signature_match(const struct persona_request *req, struct persona_result *out)
{
    if (!req || !out)
        return 0;

    for (size_t i = 0; i < sizeof(signature_table)/sizeof(signature_table[0]); i++) {
        const struct signature_rule *rule = &signature_table[i];
        if (!field_matches(rule->field, req, rule->pattern))
            continue;

        strncpy(out->persona, rule->persona, sizeof(out->persona) - 1);
        strncpy(out->priority, rule->priority, sizeof(out->priority) - 1);
        strncpy(out->policy_action, rule->policy_action, sizeof(out->policy_action) - 1);
        strncpy(out->dscp, rule->dscp, sizeof(out->dscp) - 1);

        out->persona[sizeof(out->persona) - 1] = '\0';
        out->priority[sizeof(out->priority) - 1] = '\0';
        out->policy_action[sizeof(out->policy_action) - 1] = '\0';
        out->dscp[sizeof(out->dscp) - 1] = '\0';
        out->confidence = rule->confidence;
        return 1;
    }

    return 0;
}
