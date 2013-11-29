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

/* Accept a cert in lieu of basic auth, * and set r->user based on an expression */

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "mod_auth.h"
#include "ap_expr.h"

#include "mod_ssl.h" /* ssl_var_lookup */

module AP_MODULE_DECLARE_DATA authn_certificate_module;

typedef enum {
  cert_disabled = 0,
  cert_enabled = 1,
  cert_unset = 2
} certificate_mode;

typedef struct {
    ap_expr_info_t *username;
    const char *username_str;
    certificate_mode mode;
} cert_dconf;

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = NULL;

static void *create_cert_dconf(apr_pool_t *p, char *d)
{
    cert_dconf *conf = apr_pcalloc(p, sizeof(*conf));
    conf->mode = cert_unset;    
    return conf;
}

static void *merge_cert_dconf(apr_pool_t *p, void *basev, void *overridesv)
{
   cert_dconf *base      = (cert_dconf*) basev;
   cert_dconf *overrides = (cert_dconf*) overridesv;
   cert_dconf *conf      = apr_pcalloc(p, sizeof(cert_dconf));

   conf->username     =    (overrides->username == NULL) ? base->username : overrides->username;
   conf->username_str =    (overrides->username_str == NULL) ? base->username_str : overrides->username_str;
   conf->mode         =    (overrides->mode == cert_unset) ? base->mode : overrides->mode;
   return conf;
}

static int certificate_check_authn(request_rec *r)
{
    const char *user, *err;
    cert_dconf *conf = (cert_dconf *) ap_get_module_config(r->per_dir_config, 
                                            &authn_certificate_module);

    if (conf->mode == cert_disabled || conf->username_str == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "authn_cert is is disabled, mode=%d, username=%s", conf->mode, conf->username_str);
        return DECLINED;
    }
  
    if (!ssl_var_lookup || 
        (!ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_CERT") && 
         !ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_CERTBODY"))) { 
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "No certificate");
            return DECLINED;
    }

    user = ap_expr_str_exec(r, conf->username, &err);

    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "could not evaluate user expression for URI '%s': %s", r->uri, err);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!user || !*user) { 
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "empty user expression for URI '%s': %s", r->uri, err);
        return DECLINED;
    }

    r->user = apr_pstrdup(r->pool, user);
    return OK;
}

static const char *add_cert_expr(cmd_parms * cmd, void *config, const char *args)
{
    const char *err;
    const char *userexpr = ap_getword_conf(cmd->pool, &args);


    cert_dconf *conf = (cert_dconf *) config;
    conf->username_str = userexpr;
    conf->username = ap_expr_parse_cmd(cmd, conf->username_str, AP_EXPR_FLAG_STRING_RESULT,
                                       &err, NULL);
    if (err) {
        return apr_psprintf(cmd->pool,
                "Could not set username expression '%s': %s", userexpr, err);
    }
    return NULL;
}

static int certificate_post_config(apr_pool_t *p,
                                   apr_pool_t *plog,
                                   apr_pool_t *ptemp,
                                   server_rec *s)
{
    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    return OK;
}

static const command_rec authn_certif_cmds[] = {
    AP_INIT_RAW_ARGS("CertificateUsernameExpression", add_cert_expr,
        NULL, OR_AUTHCFG, 
        "An expression to determine the username based on a client certificate"),
    AP_INIT_FLAG("CertificateUsername", ap_set_flag_slot, 
        (void*)APR_OFFSETOF(cert_dconf, mode), OR_AUTHCFG, 
        "Enable/Disable using certificates for authentication. (ON or OFF)"),
    {NULL}
};

static void authn_certificate_register_hooks(apr_pool_t *p) {
    ap_hook_check_authn(certificate_check_authn, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_post_config(certificate_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authn_certificate) = {
    STANDARD20_MODULE_STUFF,
    create_cert_dconf,
    merge_cert_dconf,
    NULL,
    NULL,
    authn_certif_cmds,
    authn_certificate_register_hooks
};
