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

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
/* for getpid() */
#include <unistd.h>
#endif
#include <ctype.h>

typedef struct {
    char *attr;
    int auth_authoritative;
    int require_all;
} ibmallgroups_config_t;

module AP_MODULE_DECLARE_DATA ibmallgroups_module;

static void *create_ibmallgroups_dir_config(apr_pool_t *p, char *d)
{
    ibmallgroups_config_t *sec =
        (ibmallgroups_config_t*)apr_pcalloc(p, sizeof(ibmallgroups_config_t));
    sec->auth_authoritative = 1;
    sec->require_all = 0;
    sec->attr = "ibm-allGroups";
    return sec;
}

static char *trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

static int ibmallgroups_check_user_access(request_rec *r)
{
    ibmallgroups_config_t *sec =
        (ibmallgroups_config_t *)ap_get_module_config(r->per_dir_config, &ibmallgroups_module);

    int m = r->method_number;

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

    register int x;
    const char *t;
    const char *w;
    int method_restricted = 0;

    const char *allgroups_attribute_name;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "[%" APR_PID_T_FMT "] >ibmallgroups %s", getpid(), r->uri);
    if (!reqs_arr) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[%" APR_PID_T_FMT "] ibmallgroups authorise: no requirements array", getpid());
        return sec->auth_authoritative? HTTP_UNAUTHORIZED : DECLINED;
    }

    /*
     * If we have been authenticated by some other module than mod_auth_ldap,
     * the req structure needed for authorization needs to be created
     * and populated with the userid and DN of the account in LDAP
     */

    /* Check that we have a userid to start with */
    if ((!r->user) || (strlen(r->user) == 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "ibmallgroups: Userid is blank, AuthType=%s",
            r->ap_auth_type);
    }
    allgroups_attribute_name = apr_pstrcat(r->pool, "AUTHENTICATE_", sec->attr);

    /* Loop through the requirements array until there's no elements
     * left, or something causes a return from inside the loop */
    for(x=0; x < reqs_arr->nelts; x++) {
        if (! (reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }
        method_restricted = 1;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "w=%s", w);
        if (strcmp(w, "ldap-ibmallgroups") == 0) {
            const char *required_value;
            char *tok_ctx = NULL;
            char *tok = NULL;
            char *allgroups_value = apr_pstrdup(r->pool, apr_table_get(r->subprocess_env, allgroups_attribute_name));

            required_value = ap_getword_conf(r->pool, &t);
            if (!required_value) { 
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ibmallgroups: required_value was null");
                continue;
            }

            if (!allgroups_value) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ibmallgroups: %s was not set in environment, " 
                              "misconfiguration or LDAP did not authenticate this user", allgroups_attribute_name );
                return DECLINED;
            }
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "[%" APR_PID_T_FMT "] ibmallgroups: allgroups_value=[%s] attr=[%s] require=[%s]", getpid(), 
                                         allgroups_value, allgroups_attribute_name, required_value);

            while (NULL != (tok = apr_strtok(allgroups_value, ";", &tok_ctx))) { 
                char *trimmed = trimwhitespace(tok);
                allgroups_value = NULL;
                if (!strcasecmp(trimmed, required_value)) { 
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[%" APR_PID_T_FMT "]ibmallgroups: returning OK %s", getpid(), r->uri);
                    return OK;
                }
            }
        }
    }

    if (!method_restricted) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[%" APR_PID_T_FMT "] ibmallgroups: agreeing because non-restricted",
                      getpid());
        return OK;
    }

    if (!sec->auth_authoritative) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[%" APR_PID_T_FMT "] ibmallgroups: declining to authorise (not authoritative)", getpid());
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "[%" APR_PID_T_FMT "] ibmallgroups: authorise: authorisation denied", getpid());
    ap_note_basic_auth_failure (r);

    return HTTP_UNAUTHORIZED;
}


static const char *set_attr(cmd_parms *cmd, void *config, const char *arg) { 
           ibmallgroups_config_t *sec = config;
           sec->attr = apr_pstrdup(cmd->pool, arg);
           return NULL;
}

static const command_rec ibmallgroups_cmds[] =
{

    AP_INIT_FLAG("IBMAllGroupsAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(ibmallgroups_config_t, auth_authoritative), OR_AUTHCFG,
                 "Set to 'off' to allow access control to be passed along to lower modules if "
                 "the UserID and/or group is not known to this module. authnz_ldap is a lower-level module."),

    AP_INIT_TAKE1("IBMALLGroupsAttr", set_attr, NULL, OR_AUTHCFG,
                  "The Tivoli attribute that returns a list of all groups, Defaults to ibm-allgroups.  You must include" 
                  " this same attribute in your AuthLDAPURL"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_authnz_ldap.c", NULL };

    ap_hook_auth_checker(ibmallgroups_check_user_access, aszPre, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ibmallgroups_module =
{
    STANDARD20_MODULE_STUFF,
    create_ibmallgroups_dir_config,   /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    ibmallgroups_cmds,                /* command apr_table_t */
    register_hooks                   /* register hooks */
};
