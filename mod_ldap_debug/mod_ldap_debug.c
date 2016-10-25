/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_ldap_debug: Flip global LDAP_OPT_DEBUG in LDAP SDK to debug LDAP issues.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_ldap.h"

#include <stdio.h>

#ifdef LDAP_OPT_DEBUG_LEVEL
#define AP_LDAP_OPT_DEBUG LDAP_OPT_DEBUG_LEVEL
#else
#ifdef LDAP_OPT_DEBUG
#define AP_LDAP_OPT_DEBUG LDAP_OPT_DEBUG
#define THELEVEL 65535
#endif
#endif

module AP_MODULE_DECLARE_DATA ldap_debug_module;

typedef struct ldapdebug_config { 
    int debug_level;
} ldapdebug_config;

static int ldap_debug_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
        ldapdebug_config *st = (ldapdebug_config*) ap_get_module_config(s->module_config, &ldap_debug_module);
         
        if (st->debug_level == -1) { 
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "ldap_debug_module: LDAP SDK debugging is disabled, see LDAPDebugLevel directive");
            return OK;
        }
#ifndef AP_LDAP_OPT_DEBUG
        else { 
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "ldap_debug_module: Don't know proper LDAP_DEBUG option for this SDK.");
            return OK;
        }
#endif

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "ldap_debug_module: setting debug parms in LDAP library to %d", st->debug_level);
#ifdef AP_LDAP_OPT_DEBUG
        int result = ldap_set_option(NULL, AP_LDAP_OPT_DEBUG, &st->debug_level);
        if (result != LDAP_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "LDAP: Could not set debug level to %d:(%d) %s", st->debug_level, result, ldap_err2string(result));
        }
#endif
    return OK;
}

static const char *set_ldap_debug(cmd_parms *cmd, void *dummy, const char *d) {
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    ldapdebug_config *st = (ldapdebug_config*) ap_get_module_config(cmd->server->module_config, &ldap_debug_module);

    if (err != NULL) {
        return err;
    }

    st->debug_level = atoi(d);

    return(NULL);
}

static void ldap_debug_register_hooks(apr_pool_t *p) {
    ap_hook_post_config(ldap_debug_post_config, NULL, NULL, APR_HOOK_LAST);
}

static void *ldap_debug_config_create(apr_pool_t *p, server_rec *s) {
    ldapdebug_config *st = (ldapdebug_config *) apr_pcalloc(p, sizeof(ldapdebug_config));
    st->debug_level = -1;
    return st;
}

static void *ldap_debug_config_merge(apr_pool_t *p, void *base, void *override) {
    ldapdebug_config *merged_config = (ldapdebug_config *) apr_pcalloc(p, sizeof(ldapdebug_config));
    ldapdebug_config *basev = (ldapdebug_config*) base;
    ldapdebug_config *overridev= (ldapdebug_config*) override;

    merged_config->debug_level = (overridev->debug_level != -1) ? overridev->debug_level : basev->debug_level;
    return merged_config;
}
static const command_rec ldap_debug_cmds[] =
{
    AP_INIT_TAKE1("LDAPDebugLevel", set_ldap_debug, NULL, RSRC_CONF, "SDK-specific debug level (OpenLDAP: 7, Tivoli: 65535)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA ldap_debug_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,  /* per-directory config creator */
    NULL,  /* dir config merger */
    ldap_debug_config_create,  /* server config creator */
    ldap_debug_config_merge,  /* server config merger */
    ldap_debug_cmds,  /* command table */
    ldap_debug_register_hooks,       /* set up other request processing hooks */
};
