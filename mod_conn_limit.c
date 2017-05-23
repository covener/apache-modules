/*
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
 *
 * Based on mod_limitipconn by David Jao and Niklas Edmundsson
 */

/* XXX: merge config */

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"

module AP_MODULE_DECLARE_DATA conn_limit_module;

static int server_limit, thread_limit, maxclients;

typedef struct {
    int maxconns;                 /* Limit on number of parallel requests      */
    int worker_threshold;         /* Free thread % threshold to enforce limits */
    apr_ipsubnet_t **unlimited;   /* Source addresses that are not limited     */
    unsigned int logonly:1;       /* TODO */
} dconf_t;

static void *create_dirconf(apr_pool_t *p, char *path)
{
    dconf_t *cfg = (dconf_t *) apr_pcalloc(p, sizeof (*cfg));
    cfg->worker_threshold = 60;   /* Default to enforcement at > 60% utilization */
    return cfg;
}

/* from mod_authz_host, collect a list of apr_ipsubnet_t's */
static const char *cmd_nolimit(cmd_parms *cmd, void *in_dconf, const char *a1)
{
    const char *t, *w;
    int count = 0;
    apr_ipsubnet_t **ip;
    apr_pool_t *ptemp = cmd->temp_pool;
    apr_pool_t *p = cmd->pool;
    dconf_t *cfg = (dconf_t *) in_dconf;
    t = a1;
    while ((w = ap_getword_conf(ptemp, &t)) && w[0])
        count++;
    if (count == 0)
        return "'ConnectionLimitUnlimitedSourceAddresses' requires an argument";

    ip = apr_pcalloc(p, sizeof(apr_ipsubnet_t *) * (count + 1));
    /* XXX: can't use multiple directives */
    cfg->unlimited = ip;

    while ((w = ap_getword_conf(ptemp, &t)) && w[0]) {
        char *addr = apr_pstrdup(ptemp, w);
        char *mask;
        apr_status_t rv;

        if ((mask = ap_strchr(addr, '/')))
            *mask++ = '\0';

        rv = apr_ipsubnet_create(ip, addr, mask, p);

        if (APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return apr_psprintf(p, "ip address '%s' appears to be invalid", w);
        }
        else if (rv != APR_SUCCESS) {
            return apr_psprintf(p, "ip address '%s' appears to be invalid: %pm",
                                w, &rv);
        }

        ip++;
    }
    return NULL;
}

/* Returns 1 if the current useragent address is unlimited */
static int ip_unlimited(request_rec *r, dconf_t *dconf)
{
    apr_ipsubnet_t **ip = dconf->unlimited;
    while (ip && *ip) {
        if (apr_ipsubnet_test(*ip, r->useragent_addr))
            return 1;
        ip++;
    }
    return 0;
}

/* Snoop on the value of MaxClients/MaxRequestWorkers */
static const char *set_max_workers(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    maxclients = atoi(arg);
    return NULL;
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                       server_rec *s)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    if (maxclients == 0 && server_limit == 1) { 
        maxclients = thread_limit; /* mpm_winnt */
    }
    return OK;
}

/* Returns 1 if the current request breaches the policy */
static int ip_breached(request_rec *r, dconf_t *cfg) 
{ 
    worker_score ws_record;
    int ip_count = 0, idle = 0, minfree = 0;
    int i = 0, j = 0;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "maxclients %d thresh %d", maxclients, cfg->worker_threshold);
    if (cfg->worker_threshold > -1 && maxclients > 0) { 
        minfree = (maxclients * cfg->worker_threshold / 100);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "minfree %d", minfree);
    }

    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(&ws_record, i, j);
            switch (ws_record.status) {
                case SERVER_BUSY_READ:
                case SERVER_BUSY_WRITE:
                case SERVER_BUSY_KEEPALIVE:
                case SERVER_BUSY_LOG:
                case SERVER_BUSY_DNS:
                case SERVER_CLOSING:
                case SERVER_GRACEFUL:
                    if (!strcmp(r->useragent_ip, ws_record.client)) { 
                        if (ip_count++ >= cfg->maxconns) {  /* we're counting ourselves */
                            return 1;
                        }
                    }
                    break;
                default:
                case SERVER_READY:
                    if (idle++ >= minfree) { 
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "no breach, too many free threads (%d)", idle);
                        return 0;
                    }
                    break;
            }
        }
    }
   
    return 0;
}

static int access_check(request_rec *r)
{ 
    dconf_t *cfg = ap_get_module_config(r->per_dir_config, &conn_limit_module);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "access_check cfg=%pp", cfg);

    if (!cfg || cfg->maxconns < 1 || !ap_is_initial_req(r)) { 
        return DECLINED;
    }

    if (ip_unlimited(r, cfg)) { 
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "IP is unlimited");
        return DECLINED;
    }

    if (ip_breached(r, cfg)) { 
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO() "breached");
        if (!cfg->logonly) { 
            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "return 503");
            return HTTP_SERVICE_UNAVAILABLE;
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "not breached");
    return DECLINED;
}


static command_rec conn_limit_cmds[] = {
    AP_INIT_RAW_ARGS("ConnectionLimitUnlimitedSourceAddresses", cmd_nolimit, NULL, 
                     RSRC_CONF,
                     "Source addresses immune to limits"),
    AP_INIT_TAKE1("ConnectionLimit", ap_set_int_slot, 
                   (void *)APR_OFFSETOF (dconf_t, maxconns), 
                   ACCESS_CONF | RSRC_CONF,
                  "Number of connections per client"),
    AP_INIT_TAKE1("ConnectionBusyThreshold", ap_set_int_slot, 
                   (void *)APR_OFFSETOF (dconf_t, worker_threshold), 
                   ACCESS_CONF | RSRC_CONF,
                  "Thread utilization minimum to enforce limits"),
    AP_INIT_TAKE1("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    AP_INIT_TAKE1("MaxClients", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    {NULL},
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    /* Let responses be served out of the cache even if they'd breach limits */
    ap_hook_access_checker(access_check, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(conn_limit) = {
    STANDARD20_MODULE_STUFF,
    create_dirconf           , /* create per-dir    */
    NULL,                      /* merge  per-dir    */
    NULL,                      /* create per-server */
    NULL,                      /* merge  per-server */
    conn_limit_cmds,           
    register_hooks
};
