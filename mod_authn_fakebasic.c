/* Copyright 2013 Eric Covener
 * Licensed to the Apache Software Foundation (ASF) under one or more
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

/* Accept SSLFakeBasic in lieu of Basic Authentication without mocking up a foo:password file.
 * - Optionally transform the r->user from SSL with a regex
 * - Optionally replace r->user with an environment variable:
 *
 *       RewriteEngine on
 *       RewriteCond %{ENV:SSL_CLIENT_CN} !^$
 *       RewriteRule .* - [E=ssl-username:%{ENV:SSL_CLIENT_CN}]

 * In 2.4 and later, use mod_authn_cert instead, which does not require SSLFakeBasic.
 */

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "mod_auth.h"
#include "ap_provider.h"

#include "http_main.h" /* ap_server_conf */

module AP_MODULE_DECLARE_DATA authn_fakebasic_module;

typedef struct {
    ap_regex_t *dn_regex; 
    const char *dn_subst;
    const char *user_envvar;
} fakebasic_dconf;

static void *create_fakebasic_dconf(apr_pool_t *p, char *d)
{
    fakebasic_dconf *conf = apr_pcalloc(p, sizeof(*conf));
    return conf;
}

static void *merge_fakebasic_dconf(apr_pool_t *p, void *basev, void *overridesv)
{
   fakebasic_dconf *base      = (fakebasic_dconf*) basev;
   fakebasic_dconf *overrides = (fakebasic_dconf*) overridesv;
   fakebasic_dconf *conf      = apr_pcalloc(p, sizeof(fakebasic_dconf));

   conf->dn_subst     =    (overrides->dn_subst == NULL) ? base->dn_subst : overrides->dn_subst;
   conf->dn_regex     =    (overrides->dn_regex == NULL) ? base->dn_regex : overrides->dn_regex;
   conf->user_envvar =    (overrides->user_envvar== NULL) ? base->user_envvar: overrides->user_envvar;
   return conf;
}

static const char *add_fakebasic_regex(cmd_parms * cmd, void *config, const char *arg1, const char *arg2)
{
    fakebasic_dconf *conf = (fakebasic_dconf *) config;
    ap_regex_t *regexp;

    regexp = ap_pregcomp(cmd->pool, arg1, AP_REG_EXTENDED);

    if (!regexp) {
        return apr_pstrcat(cmd->pool, "SSLFakeBasicReplace: cannot compile regular "
                                      "expression '", arg1, "'", NULL);
    }

    conf->dn_regex = regexp;
    conf->dn_subst = arg2;

    return NULL;
}

static const char *add_fakebasic_userenvvar(cmd_parms * cmd, void *config, const char *arg1)
{
    fakebasic_dconf *conf = (fakebasic_dconf *) config;
    conf->user_envvar = arg1;
    return NULL;
}
static authn_status check_password(request_rec *r, const char *user, const char *password)
{
    fakebasic_dconf *dconf = ap_get_module_config(r->per_dir_config, &authn_fakebasic_module);
  
    if (!password || *password == '\0') { 
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no password");
        return AUTH_USER_NOT_FOUND;
    }

    if (!ap_strstr_c(user,"=")) {  
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no password");
        return AUTH_USER_NOT_FOUND;
    }

    if (!strcasecmp(password, "password")) {
        if (dconf->user_envvar) { 
            const char *sub = apr_table_get(r->subprocess_env, dconf->user_envvar);
            if (!sub) { 
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "envvar %s not set", dconf->user_envvar);
                return AUTH_USER_NOT_FOUND;
            }
            r->user = apr_pstrdup(r->pool, sub);
        }
        else if (dconf->dn_regex) { 
            ap_regmatch_t regm[AP_MAX_REG_MATCH];
            if (!ap_regexec(dconf->dn_regex, user, AP_MAX_REG_MATCH, regm, 0)) {
                char *substituted = ap_pregsub(r->pool, dconf->dn_subst, user, AP_MAX_REG_MATCH, regm);
                if (NULL != substituted) {
                    r->user = substituted;
                }
            }
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "auth granted");
        return AUTH_GRANTED;
    }
    return AUTH_DENIED;

}
static const authn_provider authn_fakebasic_provider =
{
    &check_password,
    NULL,
};

static void authn_fakebasic_register_hooks(apr_pool_t *p) {
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "fakebasic", "0",
                         &authn_fakebasic_provider);
}

static const command_rec authn_fakebasic_cmds[] = {
    AP_INIT_TAKE2("SSLFakeBasicReplace", add_fakebasic_regex,
        NULL, OR_AUTHCFG, 
        "An expression to determine the username based on a client certificate (modifies the copy of the DN)"),
    AP_INIT_TAKE1("SSLFakeBasicUsernameEnvvar", add_fakebasic_userenvvar,
        NULL, OR_AUTHCFG, 
        "Replace r->user with the value of the named environmen variable"),
    {NULL}
};


module AP_MODULE_DECLARE_DATA authn_fakebasic_module = { 
    STANDARD20_MODULE_STUFF,
    create_fakebasic_dconf,
    merge_fakebasic_dconf,
    NULL,
    NULL,
    authn_fakebasic_cmds,
    authn_fakebasic_register_hooks
};
