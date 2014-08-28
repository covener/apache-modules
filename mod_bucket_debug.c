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
 * mod_bucket_debug: trace bucket structures in input filter
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#include "http_protocol.h"

static const char filter_name[] = "BUCKET_DEBUG";
module AP_MODULE_DECLARE_DATA bucket_debug_module;

static const char *mode2string[] = { "AP_MODE_READBYTES", "AP_MODE_GETLINE", "AP_MODE_EATCRLF", "AP_MODE_SPECULATIVE", "AP_MODE_EXHAUSTIVE", "AP_MODE_INIT"};
static const char *block2string[] = { "APR_BLOCK_READ", "APR_NONBLOCK_READ"};

static apr_status_t debug_in_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes)
{
    apr_bucket *e;
    conn_rec *c = f->c;
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "entry, bb=%pp block=%s mode=%s readbytes=%"APR_OFF_T_FMT, bb, block2string[block], mode2string[mode], readbytes); 

    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS) { 
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, rv, c, "ap_get_brigade error");
        return rv;
    }

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        const char *data;
        apr_size_t len;
          
        if (APR_BUCKET_IS_EOS(e)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "EOS BUCKET"); 
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "FLUSH BUCKET"); 
        }
        else if (APR_BUCKET_IS_METADATA(e)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "METADATA BUCKET"); 
        }
        else { 
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "%s BUCKET data length %" APR_OFF_T_FMT, e->type->name, len); 
        }
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c, "exit");
    return rv;
}

static void register_hooks(apr_pool_t * p)
{
    ap_register_input_filter(filter_name, debug_in_filter, NULL,  AP_FTYPE_CONNECTION + 8);
}

AP_DECLARE_MODULE(bucket_debug) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};
