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
 *
 */


/* covener@apache.org
 * This module lets you insert or replace cookie paths w/o mod_proxy
 */

#include <unistd.h>

#include "apr_strings.h"
#include "apr_lib.h"

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"

module AP_MODULE_DECLARE_DATA cookie_cutter_module;

static const char *cc_setpath(request_rec *r, const char *headerval, const char *path) { 
    char *setcookie, *last1, *next, *prev;
    char *ret = NULL;
    int inlen = strlen(headerval);
    setcookie = apr_pstrdup(r->pool, headerval);
    apr_strtok(setcookie, "=;", &last1); /* throw away cookie name */
    while((next = apr_strtok(NULL, "=;\t ", &last1))) { 
        if (!strcasecmp(next, "Path")) { 
            /* If there's a Path, we'll cut it out and insert the new one */
            char *prefix_end = prev + strlen(prev);
            char *suffix = NULL;
            next = apr_strtok(NULL, "=;\t ", &last1);
            if (!strcasecmp(path, next)) { 
                /* Path was already correct */
                return headerval;
            }
            suffix = apr_strtok(NULL, ";=\t ", &last1);
            ret = apr_pcalloc(r->pool, (prefix_end - setcookie) + 1); 
            memcpy(ret, headerval, prefix_end - setcookie);
            ret = apr_pstrcat(r->pool, ret, "; Path=", path, NULL);
            if (suffix) { 
               ret = apr_pstrcat(r->pool, ret, "; ", (headerval + (suffix-setcookie)), NULL);
            }
        }
        prev = next;
    }
 
    if (!ret) { 
        /* There was no Path,just append */
        ret = apr_psprintf(r->pool, "%s ; Path=%s", headerval, path);
    }

    return ret;
}

typedef struct {
    apr_array_header_t *setpath;
} cc_dirconf;

typedef struct {
    const char *cookie_name;
    const char *path;
} cc_entry;

/* edit_do is used for Header edit to iterate through the headers */
typedef struct {
    request_rec *r;
    cc_entry *hdr;
    apr_table_t *t;
} edit_do;


static int edit_cookie(void *v, const char *key, const char *val)
{
    edit_do *ed = (edit_do *)v;
    const char *repl = val;
    if (strcasecmp(key, "Set-Cookie")) return 0;

    if (ap_strstr_c(val, ed->hdr->cookie_name) == val) { 
        const char *next = val+strlen(ed->hdr->cookie_name);
        if (*next == '\0' || *next == ';' || *next == '=') { 
            repl = cc_setpath(ed->r, val, ed->hdr->path);
        }
    }

    
    if (repl == NULL)
        return 0;

    apr_table_addn(ed->t, key, repl);
    return 1;
}

static int add_them_all(void *v, const char *key, const char *val)
{
    apr_table_t *headers = (apr_table_t *)v;
    apr_table_addn(headers, key, val);
    return 1;
}

static apr_status_t cc_output_filter (ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    int i = 0;
    apr_array_header_t *it;
    cc_dirconf *dirconf = ap_get_module_config(f->r->per_dir_config, &cookie_cutter_module);
    it = dirconf->setpath;

    for (i = 0; i < it->nelts; ++i) {
        cc_entry *hdr = &((cc_entry*) (it->elts))[i];
        if (apr_table_get(f->r->headers_out, "Set-Cookie")) {
            edit_do ed;
            ed.r = f->r;
            ed.hdr = hdr;
            ed.t = apr_table_make(f->r->pool, 5);
            if (!apr_table_do(edit_cookie, (void *) &ed, f->r->headers_out, "Set-Cookie", NULL)) { 
                    return 0;
            }
            apr_table_unset(f->r->headers_out, "Set-Cookie");
            apr_table_do(add_them_all, (void *) f->r->headers_out, ed.t, NULL);
        }
    }
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next,in);
}


static const char *set_cookie_force_path(cmd_parms *cmd, void *indc, const char *arg1, const char *arg2) 
{
   cc_entry *new;
   cc_dirconf *dirconf = (cc_dirconf*) indc;
   new = (cc_entry *) apr_array_push(dirconf->setpath);
   new->cookie_name = arg1;
   new->path = arg2;
   return NULL;
}

static void *create_cc_dir_config(apr_pool_t *p, char *d)
{
    cc_dirconf *conf = apr_pcalloc(p, sizeof(*conf));
    conf->setpath= apr_array_make(p, 2, sizeof(cc_entry));
    return conf;
}

static const command_rec cmds[] =
{
    AP_INIT_TAKE2("CookieForcePath", set_cookie_force_path, NULL, OR_FILEINFO, "Change set-cookie path"),
    {NULL}
};

static void cc_insert_output_filter(request_rec *r)
{
    cc_dirconf *dirconf = ap_get_module_config(r->per_dir_config, &cookie_cutter_module);

    if (dirconf->setpath->nelts) {
        ap_add_output_filter("CUT_COOKIES_OUT", NULL, r, r->connection);
    }
}

static void cc_register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("CUT_COOKIES_OUT", cc_output_filter, NULL, AP_FTYPE_CONTENT_SET+1); /* after mod_headers for testing */
    ap_hook_insert_filter(cc_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA cookie_cutter_module = { 
    STANDARD20_MODULE_STUFF,
    create_cc_dir_config,
    NULL,
    NULL,
    NULL,
    cmds,                       /* command table */
    cc_register_hooks
};
