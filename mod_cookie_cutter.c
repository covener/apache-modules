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
 * This module lets you do unusual things with cookies:
 *  - Insert or replace cookie paths w/o mod_proxy
 *  - Report when an incoming Cookie value looks too large
 *  - Report when an outgoing Set-Cookie header looks too large
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

typedef struct {
    apr_array_header_t *setpath;
    int max_cookie;
    int max_setcookie;
} cc_dirconf;

typedef struct {
    const char *cookie_name;
    const char *path;
} cc_entry;

/* edit_do is used for Header edit to iterate through the headers */
typedef struct {
    request_rec *r;
    cc_dirconf *dirconf;
    cc_entry *hdr;
    apr_table_t *t;
} edit_do;


static const char *cookie_get_name(request_rec *r, const char *headerval, int inlen) { 
    char *last1;
    return apr_strtok(apr_pstrdup(r->pool, headerval), "=;", &last1);
}

static const char *cookie_get_field(request_rec *r, const char *headerval, int inlen, char *field) { 
    char *setcookie, *last1, *next;
    setcookie = apr_pstrdup(r->pool, headerval);
    apr_strtok(setcookie, ";", &last1); /* throw away cookie name */
    while((next = apr_strtok(NULL, ";", &last1))) { 
        char *eqlast;
        next = apr_strtok(next, "=", &eqlast);
        while(next && *next == ' ') next++;
        if (next && !strcasecmp(next, field)) { 
            next = apr_strtok(NULL, "=", &eqlast);
            return next;
        }
    }
    return NULL;
}

static const char *cc_setpath(request_rec *r, const char *headerval, const char *path) { 
    char *setcookie, *last1, *next;
    char *ret = NULL;
    setcookie = apr_pstrdup(r->pool, headerval);
    apr_strtok(setcookie, ";", &last1); /* throw away cookie name */
    while((next = apr_strtok(NULL, ";", &last1))) { 
        char *eqlast;
        char *pathstart = next;
        char *justpath = apr_strtok(next, "=", &eqlast);
        while(next && *next == ' ') next++;
        if (!strcasecmp(next, "Path")) { 
            /* If there's a Path, we'll cut it out and insert the new one */
            char *suffix = NULL;
            next = apr_strtok(NULL, "=", &eqlast);
            while(next && *next == ' ') next++;
            if (!strcasecmp(path, next)) { 
                /* Path was already correct */
                return headerval;
            }
            suffix = apr_strtok(NULL, ";", &last1);
            ret = apr_pcalloc(r->pool, (pathstart - setcookie) + 1); 
            memcpy(ret, headerval, pathstart - setcookie -1);
            ret = apr_pstrcat(r->pool, ret, "; Path=", path, NULL);
            if (suffix) { 
               ret = apr_pstrcat(r->pool, ret, "; ", (headerval + (suffix-setcookie)), NULL);
            }
        }
    }
 
    if (!ret) { 
        /* There was no Path,just append */
        ret = apr_psprintf(r->pool, "%s ; Path=%s", headerval, path);
    }

    return ret;
}


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

static int checklen(void *v, const char *key, const char *val)
{
    edit_do *ed = (edit_do *)v;
    int len = strlen(val);
    if (ed->dirconf->max_cookie > 0 && !strcasecmp(key, "Cookie")) { 
        char *copy = apr_pstrdup(ed->r->pool, val);
        char *name, *val, *last;
        while((name = apr_strtok(copy, ";", &last))) { 
            char *last2=NULL;
            int val_len;
            copy = NULL; /* keep on tokin */
            name = apr_strtok(name, "=", &last2);
            while(name && *name== ' ') name++;
            val  =  apr_strtok(NULL, "=", &last2);
            val_len = val ? strlen(val) : 0;
            if (val && val_len > ed->dirconf->max_cookie) { 
                const char *oldmsg = apr_table_get(ed->r->subprocess_env, "ibm-long-cookie");
                char *msg = apr_psprintf(ed->r->pool, "C:%s|%d", name, val_len);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ed->r, "Cookie too long: %s", msg);
                apr_table_set(ed->r->subprocess_env, "ibm-long-cookie", apr_psprintf(ed->r->pool, "%s%s%s", 
                            oldmsg ? oldmsg : "", 
                            oldmsg ? ", ": "", 
                            msg));
            }
        }
    }
    if (ed->dirconf->max_setcookie > 0 && !strcasecmp(key, "Set-Cookie")) { 
        if (len > ed->dirconf->max_setcookie) { 
            const char *oldmsg = apr_table_get(ed->r->subprocess_env, "ibm-long-cookie");
            char *msg = apr_psprintf(ed->r->pool, "SC:%s|P:%s|D:%s|%d", 
                          cookie_get_name(ed->r, val, len), 
                          cookie_get_field(ed->r, val, len, "Path"), 
                          cookie_get_field(ed->r, val, len, "Domain"), 
                          len );
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ed->r, "Set-Cookie too long: %s", msg);
            apr_table_set(ed->r->subprocess_env, "ibm-long-cookie", apr_psprintf(ed->r->pool, "%s%s%s", 
                          oldmsg ? oldmsg : "", 
                          oldmsg ? ", ": "", 
                          msg));
        }
    }

    return 1;
}


static int add_them_all(void *v, const char *key, const char *val)
{
    apr_table_t *headers = (apr_table_t *)v;
    apr_table_addn(headers, key, val);
    return 1;
}

static apr_status_t cc_output_filter(ap_filter_t *f, apr_bucket_brigade *in)
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

    if (dirconf->max_cookie > 0) { 
        edit_do ed;
        ed.dirconf = dirconf;
        ed.r = f->r;
        if (!apr_table_do(checklen, (void *) &ed, f->r->headers_in, "Cookie", NULL)) { 
            return 0;
        }
    }
    if (dirconf->max_setcookie > 0) { 
        edit_do ed;
        ed.dirconf = dirconf;
        ed.r = f->r;
        if (!apr_table_do(checklen, (void *) &ed, f->r->headers_out, "Set-Cookie", NULL)) { 
            return 0;
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
static const char *set_cookie_maxsetcookie(cmd_parms *cmd, void *indc, const char *arg1) 
{
   cc_dirconf *dirconf = (cc_dirconf*) indc;
   dirconf->max_setcookie = atoi(arg1);
   return NULL;
}
static const char *set_cookie_maxcookie(cmd_parms *cmd, void *indc, const char *arg1) 
{
   cc_dirconf *dirconf = (cc_dirconf*) indc;
   dirconf->max_cookie = atoi(arg1);
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
    AP_INIT_TAKE1("CookieMaxSetCookie", set_cookie_maxsetcookie, NULL, OR_FILEINFO, "report on set-cookie greater than specified bytes"),
    AP_INIT_TAKE1("CookieMaxCookie", set_cookie_maxcookie, NULL, OR_FILEINFO, "report on set-cookie greater than specified bytes"),
    {NULL}
};

static void cc_insert_output_filter(request_rec *r)
{
    cc_dirconf *dirconf = ap_get_module_config(r->per_dir_config, &cookie_cutter_module);
    if (dirconf->setpath->nelts || dirconf->max_cookie > 0 || dirconf->max_setcookie > 0) {
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
