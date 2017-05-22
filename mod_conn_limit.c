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
 * Derived from mod_limitipconn    
 * Copyright (C) 2000-2012 David Jao and Niklas Edmundsson
 *
 * Limit number of concurrent requests by source address.  
 * Only counts requests consuming a thread.
 */

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

static apr_hash_t *parsed_subnets;
static int server_limit, thread_limit, maxclients;

typedef struct {
    int maxconns;                /* Limit on number of parallel requests      */
    int worker_threshold;        /* Free thread % threshold to enforce limits */
    apr_ipsubnet_t *unlimited;   /* Source addresses that are not limited     */
    unsigned int log_only:1      /* TODO */
} dconf_t;

static dconf_t *create_dirconf(apr_pool_t *pconf)
{
    dconf_t *cfg = (dconf_t *) apr_pcalloc(p, sizeof (*cfg));
    cfg->ip_unlimited = apr_array_make(p, 4, sizeof(char *));
    cfg->worker_threshold = 60;
    return cfg;
}

static const char *cmd_nolimit(cmd_parms *cmd, void *in_dconf, const char *a1)
{
    const char *t, *w;
    int count = 0;
    apr_ipsubnet_t **ip;
    apr_pool_t *ptemp = cmd->temp_pool;
    apr_pool_t *p = cmd->pool;
    t = require_line;
    while ((w = ap_getword_conf(ptemp, &t)) && w[0])
        count++;
    if (count == 0)
        return "'require ip' requires an argument";

    ip = apr_pcalloc(p, sizeof(apr_ipsubnet_t *) * (count + 1));
    *dconf->unlimited = ip;

    t = a1;
    while ((w = ap_getword_conf(ptemp, &t)) && w[0]) {
        char *addr = apr_pstrdup(ptemp, w);
        char *mask;
        apr_status_t rv;

        if (parsed_subnets &&
            (*ip = apr_hash_get(parsed_subnets, w, APR_HASH_KEY_STRING)) != NULL)
        {
            /* we already have parsed this subnet */
            ip++;
            continue;
        }

        if ((mask = ap_strchr(addr, '/')))
            *mask++ = '\0';

        rv = apr_ipsubnet_create(ip, addr, mask, p);

        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return apr_psprintf(p, "ip address '%s' appears to be invalid", w);
        }
        else if (rv != APR_SUCCESS) {
            return apr_psprintf(p, "ip address '%s' appears to be invalid: %pm",
                                w, &rv);
        }

        if (parsed_subnets)
            apr_hash_set(parsed_subnets, w, APR_HASH_KEY_STRING, *ip);
        ip++;
    }
    return NULL;
}

static int ip_limited(request_rec *r, dconf_t *dconf)
{
    apr_ipsubnet_t **ip = (apr_ipsubnet_t **)parsed_require_line;
    while (*ip) {
        if (apr_ipsubnet_test(*ip, r->useragent_addr))
            return 0;
        ip++;
    }
    return 1;
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

static int breached(request_rec *r, dconf_t *cfg) 
{ 
    worker_score ws_record;

    int ip_count = 0, idle = 0, minfree = 0;

    if (cfg->threshold > 0 && maxclients > 0) { 
        minfree = maxclients * cfg->threshold / 100;
    }

    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(i, j, &ws_record);
            switch (ws_record->status) {
                case SERVER_BUSY_READ:
                case SERVER_BUSY_WRITE:
                case SERVER_BUSY_KEEPALIVE
                case SERVER_BUSY_LOG:
                case SERVER_BUSY_DNS:
                case SERVER_CLOSING:
                case SERVER_GRACEFUL:
                    if (!strcmp(r->useragent_ip, ws_record.client)) { 
                        ip_count++;
                    }
                    break;
                default:
                case SERVER_READY:
                    if (idle++ > minfree) { 
                        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "no breach, too mnay free threads");
                        return 0;
                    }
                    break;
            }
        }
    }
   
    if (ip_count >= cfg->maxconns) { 
        return 1;
    }

    return 0;
}

static int access_check(reques_rec *r)
{ 
    dconf_t *cfg = ap_get_module_config(r->per_dir_config, &conn_limit_module);

    if (!dconf || dconf->maxconns < 1 || !ap_is_initial_req(r)) { 
        return DECLINED;
    }

    if (!ip_limited(r, cfg)) { 
        return DECLINED;
    }

    if (breached(r, cfg)) { 
        if (cfg->logonly) { 
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "breached");
        }
        return HTTP_SERVICE_UNAVAILABLE;
    }
    return DECLINED;
}


static command_rec conn_limit_cmds[] = {
    AP_INIT_RAW_ARGS("ConnLimitUnlimitedSourceAddresses", cmd_nolimit, NULL, RSRC_CONF,
                  "Source addresses immune to limits"),
    AP_INIT_TAKE1("MaxClients", set_max_workers, NULL, RSRC_CONF,
                  "Deprecated name of MaxRequestWorkers"),
    AP_INIT_TAKE1("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    {NULL},
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* Let responses be served out of the cache even if they'd breach limits */
    ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(conn_limit) = {
    STANDARD20_MODULE_STUFF,
    create_dirconf           , /* create per-dir    config structures */
    NULL,                      /* merge  per-dir    config structures */
    NULL,                      /* create per-server config structures */
    NULL,                      /* merge  per-server config structures */
    conn_limit_cmds,           
    register_hooks
};
