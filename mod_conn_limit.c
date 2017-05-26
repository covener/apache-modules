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

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_PROCESS_H
#include <process.h>            /* for getpid() on Win32 */
#endif

module AP_MODULE_DECLARE_DATA conn_limit_module;

static int server_limit, thread_limit, max_threads, maxclients, my_slot;

typedef struct {
    int maxconns;                 /* Limit on number of parallel requests      */
    int worker_threshold;         /* Free thread % threshold to enforce limits */
    int local_worker_threshold;   /* Free thread % threshold in current proc   */
    apr_ipsubnet_t **unlimited;   /* Source addresses that are not limited     */

    unsigned int logonly:1;       /* TODO */

    unsigned int maxconns_set:1;   
    unsigned int worker_threshold_set:1;   
    unsigned int local_worker_threshold_set:1;   
    unsigned int unlimited_set:1;   
    unsigned int reserved:27;   
} dconf_t;

static void *create_dirconf(apr_pool_t *p, char *path)
{
    dconf_t *cfg = (dconf_t *) apr_pcalloc(p, sizeof (*cfg));
    cfg->maxconns = cfg->worker_threshold = cfg->local_worker_threshold = -1;
    return cfg;
}

static void *merge_dirconf(apr_pool_t *p, void *basev, void *overridesv)
{
    dconf_t *a, *base, *over;

    a     = (dconf_t *)apr_pcalloc(p, sizeof(dconf_t));
    base  = (dconf_t *)basev;
    over  = (dconf_t *)overridesv;
  
    a->maxconns = over->maxconns != -1 ? over->maxconns : base->maxconns;
    a->worker_threshold = over->worker_threshold != -1 ? 
                          over->worker_threshold : base->worker_threshold;
    a->local_worker_threshold = over->maxconns != -1 ? 
                          over->maxconns : base->maxconns;

    /* not additive */
    a->unlimited = over->unlimited_set ? over->unlimited : base->unlimited;

    return a;
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

    while ((w = ap_getword_conf(ptemp, &t)) && w[0]) count++;
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

static void child_init(apr_pool_t *pchild, server_rec *s)
{
    apr_proc_t pid;
    pid.pid = getpid();
    my_slot = ap_find_child_by_pid(&pid);
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                       server_rec *s)
{
  
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
    if (maxclients == 0 && server_limit == 1) { 
        maxclients = max_threads; /* mpm_winnt */
    }
    return OK;
}

/* Returns 1 if the current request breaches the policy */
static int ip_breached(request_rec *r, dconf_t *cfg) 
{ 
    worker_score ws_record;
    int ip_count = 0, idle = 0, minfree = 0, local_minfree = 0;
    int i = 0, j = 0;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "maxconns %d maxthreads %d maxclients %d thresh %d local_thresh %d my_slot=%d", 
                  cfg->maxconns, max_threads, maxclients, cfg->worker_threshold, cfg->local_worker_threshold, my_slot);

    if (cfg->worker_threshold > -1 && maxclients > 0) { 
        minfree = (maxclients * cfg->worker_threshold / 100);
    }
    if (cfg->local_worker_threshold > -1 && max_threads > 0) { 
        local_minfree = (max_threads * cfg->local_worker_threshold / 100);
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "minfree %d local_minfree %d", minfree, local_minfree);

    /* Check for idle threads in local process */
    if (local_minfree > 0) {  
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(&ws_record, my_slot, j);
            if (ws_record.status == SERVER_READY && idle++ >= local_minfree) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "no breach, too many free threads in this process (%d/%d)", idle, max_threads);
                return 0;
            }
        }
    } 

    /* Check for global idle threads & global connections from this IP */
    for (i = 0, idle = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(&ws_record, i, j);
            if (ws_record.status == SERVER_READY) { 
                if (idle++ >= minfree) { 
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "no breach, too many free threads (%d/%d)", idle, max_threads);
                    return 0;
                }
            }
            else if (!strcmp(r->useragent_ip, ws_record.client)) { 
                ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "  MATCH: uri=%s status=%d", ws_record.request, ws_record.status);
                if (++ip_count > cfg->maxconns) { 
                    /* don't count ourself. Logged by caller */
                    return 1;
                }
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
                     "Source addresses immune to connection limits"),
    AP_INIT_TAKE1("ConnectionLimit", ap_set_int_slot, 
                   (void *)APR_OFFSETOF (dconf_t, maxconns), 
                   ACCESS_CONF | RSRC_CONF,
                  "Number of active connections per client IP"),
    AP_INIT_TAKE1("ConnectionLimitBusyThreshold", ap_set_int_slot, 
                   (void *)APR_OFFSETOF (dconf_t, worker_threshold), 
                   ACCESS_CONF | RSRC_CONF,
                  "Global thread utilization minimum needed to enforce limits"),
    AP_INIT_TAKE1("ConnectionLimitBusyThresholdLocal", ap_set_int_slot, 
                   (void *)APR_OFFSETOF (dconf_t, local_worker_threshold), 
                   ACCESS_CONF | RSRC_CONF,
                  "Local process thread utilization minimum needed to enforce limits"),
    AP_INIT_TAKE1("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    AP_INIT_TAKE1("MaxClients", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time"),
    {NULL},
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
    /* Let responses be served out of the cache even if they'd breach limits */
    ap_hook_access_checker(access_check, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(conn_limit) = {
    STANDARD20_MODULE_STUFF,
    create_dirconf           , /* create per-dir    */
    merge_dirconf,             /* merge  per-dir    */
    NULL,                      /* create per-server */
    NULL,                      /* merge  per-server */
    conn_limit_cmds,           
    register_hooks
};
