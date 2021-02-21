/*
 * Copyright 2020-2021 Riccardo Vacirca
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "ctype.h"
#include "time.h"
#include "pthread.h"

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_dbd.h"
#include "apr_uri.h"
#include "apr_escape.h"
#include "apr_md5.h"
#include "apr_base64.h"
#include "apr_strmatch.h"
#include "apr_network_io.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"

#include "mod_watchdog.h"
#include "mod_dbd.h"

#include "openssl/engine.h"
#include "openssl/hmac.h"
#include "openssl/evp.h"

#include "util_script.h"

#define Q2_HT_METHOD_GET          0x01
#define Q2_HT_METHOD_POST         0x02
#define Q2_HT_METHOD_PUT          0x03
#define Q2_HT_METHOD_PATCH        0x04
#define Q2_HT_METHOD_DELETE       0x05

#define Q2_DBD_MYSQL              0x01
#define Q2_DBD_PGSQL              0x02
#define Q2_DBD_SQLT3              0x03
#define Q2_DBD_MSSQL              0x04

#define Q2_RL_11REL               0x01
#define Q2_RL_1MREL               0x02
#define Q2_RL_MMREL               0x03

#define Q2_INT                    0x01
#define Q2_STRING                 0x02
#define Q2_ARRAY                  0x03
#define Q2_TABLE                  0x04

#define Q2_OUTPUT_S               "{"                                          \
                                  "\"err\":%d,"                                \
                                  "\"log\":%s,"                                \
                                  "\"http_method\":%s,"                        \
                                  "\"dbd_driver_name\":%s,"                    \
                                  "\"db_server_vers\":%s,"                     \
                                  "\"table\":%s,"                              \
                                  "\"column\":%s,"                             \
                                  "\"sql\":%s,"                                \
                                  "\"attributes\":%s,"                         \
                                  "\"results\":%s,"                            \
                                  "\"next\":%s,"                               \
                                  "\"affected_rows\":%d,"                      \
                                  "\"last_insert_id\":%s"                      \
                                  "}"

#define Q2_REST_CSET_UTF8         "charset=UTF-8"
#define Q2_REST_ACCEPT_JSON       "application/json"
#define Q2_REST_ACCEPT_JSON_UTF8  Q2_REST_ACCEPT_JSON ";" Q2_REST_CSET_UTF8
#define Q2_REST_CTYPE_TEXT        "text/plain"
#define Q2_REST_CTYPE_JSON        "application/json"
#define Q2_REST_CTYPE_FORM        "application/x-www-form-urlencoded"
#define Q2_REST_CTYPE_TEXT_UTF8   Q2_REST_CTYPE_TEXT ";" Q2_REST_CSET_UTF8
#define Q2_REST_CTYPE_JSON_UTF8   Q2_REST_CTYPE_JSON ";" Q2_REST_CSET_UTF8
#define Q2_REST_CTYPE_FORM_UTF8   Q2_REST_CTYPE_FORM ";" Q2_REST_CSET_UTF8

#define SHA256_DIGEST_SIZE        (256/8)

#define Q2_REST_ASYNC_HEADER      "Q2-Async"
#define Q2_REST_ASYNC_URI         "/q2/v1/async/%s"
#define Q2_REST_ASYNC_FSTATUS     "%s/_%s"
#define Q2_REST_ASYNC_STATUS      "{\"status\":\"%s\"}"
#define Q2_REST_ASYNC_FREQUEST    "%s/%s"
#define Q2_REST_ASYNC_PROGRESS    "1"
#define Q2_REST_ASYNC_DONE        "2"
#define Q2_REST_ASYNC_REQUEST     "%s\r\n"\
                                  "Host: %s\r\n"\
                                  "Accept: %s\r\n"\
                                  "Content-Type: %s\r\n"\
                                  Q2_REST_ASYNC_HEADER ": %s\r\n"\
                                  "Authentication: %s\r\n"\
                                  "Date: %s\r\n\r\n"\
                                  "%s"

#define Q2_REST_WD_HOST           "debian.local"
#define Q2_REST_WD_PORT           80
#define Q2_REST_WD_MAX_THREADS    10
#define Q2_REST_WD_DIROPT         APR_FINFO_DIRENT|APR_FINFO_TYPE|APR_FINFO_NAME
#define Q2_REST_WD_SOCK_TIMEOUT   (APR_USEC_PER_SEC * 30)
#define Q2_REST_WD_BUFSIZE        4096
#define Q2_REST_WD_SECOND         1000000

#ifdef _DEBUG
#ifndef _APMOD
#define log(fmt, ...) do { printf(fmt, __VA_ARGS__); } while(0)
#endif
#else
#define log(fmt, ...)
#endif

#define q2_log_error(q2, fmt, ...) do {                                        \
    q2->error = 1;                                                             \
    if (q2->log == NULL) {                                                     \
        q2->log = apr_psprintf(q2->pool,                                       \
                               "%s:%d:%s(): " fmt,                             \
                               __FILE__,                                       \
                               __LINE__,                                       \
                               __func__,                                       \
                               __VA_ARGS__);                                   \
    }                                                                          \
} while(0)

typedef apr_array_header_t*
    (*q2_tb_name_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_cl_name_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_cl_attr_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_pk_attr_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_fk_tabs_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_fk_attr_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_un_attr_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       int*);

typedef apr_array_header_t*
    (*q2_id_last_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       const char*,
                       const char*,
                       int*);
typedef const char*
    (*q2_db_vers_fn_t)(apr_pool_t*,
                       const apr_dbd_driver_t*,
                       apr_dbd_t*,
                       int*);

typedef struct q2_t {
    int error;
    const char *log;
    apr_pool_t *pool;
    const apr_dbd_driver_t *dbd_driver;
    apr_dbd_t* dbd_handle;
    int dbd_server_type;
    apr_array_header_t *attributes;
    const char *sql;
    apr_array_header_t* results;
    int affected_rows;
    const char* last_insert_id;
    q2_tb_name_fn_t tb_name_fn;
    q2_cl_name_fn_t cl_name_fn;
    q2_cl_attr_fn_t cl_attr_fn;
    q2_pk_attr_fn_t pk_attr_fn;
    q2_fk_tabs_fn_t fk_tabs_fn;
    q2_fk_attr_fn_t fk_attr_fn;
    q2_un_attr_fn_t un_attr_fn;
    q2_id_last_fn_t id_last_fn;
    q2_db_vers_fn_t db_vers_fn;
    const char *dbd_server_version;
    int next_page;
    const char *next;
    apr_array_header_t *uri_tables;
    apr_array_header_t *uri_keys;
    const char *table;
    const char* request_uri;
    int tab_relation;
    const char *column;
    apr_array_header_t *pk_attrs;
    apr_array_header_t *unsigned_attrs;
    apr_array_header_t *refs_attrs;
    apr_table_t *request_params;
    const char *request_query;
    const char *request_rawdata;
    int request_rawdata_len;
    apr_table_t *r_params;
    apr_table_t *r_others;
    int request_method;
    const char *request_method_name;
    int pagination_ppg;
    int query_num_rows;
    int single_entity;
#ifdef _APMOD
    request_rec *r_rec;
#endif
} q2_t;


static int q2_rand(int low, int upp)
{
    srand(time(NULL));
    return (rand() % (upp - low + 1)) + low;
}

static int q2_is_empty_s(const char *s)
{
    return (int)(s == NULL || (strlen(s) <= 0) || (strncmp(s, " ", 1) == 0));
}

static int q2_is_null_s(const char *s)
{
    return (int)(s == NULL || (strncasecmp(s, "null", 4)) == 0 ||
                              (strncasecmp(s, "NULL", 4)) == 0);
}

static int q2_is_integer(const char *v)
{
    char tmp[16] = {0};
    if (v == NULL) return 0;
    sprintf(tmp, "%d", atoi(v));
    return (int)(atoi(v) && (int)strlen(tmp) == (int)strlen(v));
}

static int q2_is_float(const char *v)
{
    int len;
    float dummy = 0.0;
    return (int)(sscanf(v, "%f %n", &dummy, &len)==1 && len==(int)strlen(v));
}

static int q2_in_string(const char *s, char v)
{
    for (int i = 0; i < strlen(s); i ++)
        if (s[i] == v) return 1;
    return 0;
}

static char* q2_ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

static char* q2_rtrim(char *s)
{
    char *back = s + strlen(s);
    while (isspace(*--back));
    *(back + 1) = '\0';
    return s;
}

static char* q2_trim(char *s)
{
    return q2_rtrim(q2_ltrim(s));
}

static void q2_strip_spaces(char *s)
{
    const char *d = s;
    do {while (*d == ' ') ++d;} while (*s++ = *d++);
}

static apr_array_header_t* q2_split(apr_pool_t *mp,
                                    const char *s,
                                    const char *sep)
{
    char *tok, *last, *str_c;
    apr_array_header_t *a;
    if ((str_c = apr_pstrdup(mp, s)) == NULL) return NULL;
    if ((a = apr_array_make(mp, 0, sizeof(char*))) == NULL) return NULL;
    last = NULL;
    tok = apr_strtok(str_c, sep, &last);                 //| first token
    while (*last) {
        APR_ARRAY_PUSH(a, char*) = apr_pstrdup(mp, tok); //| curr token
        tok = apr_strtok(last, sep, &last);              //| next token
    }
    APR_ARRAY_PUSH(a, char*) = apr_pstrdup(mp, tok);     //| last token
    return a;
}

static char* q2_join(apr_pool_t *mp, apr_array_header_t *arr, const char *sep)
{
    char *item = NULL;
    apr_array_header_t *tmp = NULL;
    if (mp == NULL || arr == NULL || arr->nelts <= 0) return NULL;
    for (int i = 0; i<arr->nelts; i ++) {
        item = APR_ARRAY_IDX(arr, i, char*);
        if (item != NULL) {
            if (tmp == NULL) {
                tmp = apr_array_make(mp, arr->nelts, sizeof(char*));
                if (tmp == NULL) return NULL;
            }
            APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
            if ((sep != NULL) && (i < (arr->nelts - 1)))
                APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sep);
        }
    }
    return apr_array_pstrcat(mp, tmp, 0);
}

static int q2_args_to_table(apr_pool_t *mp, apr_table_t **tab, const char *args)
{
    char *item, *key, *val;
    apr_array_header_t *qs_pair, *qs_arr;
    (*tab) = NULL;
    if (args == NULL || strlen(args) <= 0) return 1;
    qs_arr = q2_split(mp, args, "&");
    if (qs_arr->nelts <= 0) return 1;
    for (int i = 0; i < qs_arr->nelts; i ++) {
        item = APR_ARRAY_IDX(qs_arr, i, void*);
        qs_pair = q2_split(mp, item, "=");
        if (qs_pair->nelts < 2) return 1;
        if ((*tab) == NULL)
            if (((*tab) = apr_table_make(mp, qs_arr->nelts)) == NULL)
                return 1;
        key = APR_ARRAY_IDX(qs_pair, 0, void*);
        val = APR_ARRAY_IDX(qs_pair, 1, void*);
        apr_table_set((*tab), key, val);
    }
    return 0;
}

static const char* q2_table_to_args(apr_pool_t *mp, apr_table_t *table)
{
    apr_array_header_t *retv = apr_array_make(mp, 0, sizeof(char*));
    if (table != NULL) {
        if ((apr_table_elts(table))->nelts > 0) {
            for (int i = 0; i < (apr_table_elts(table))->nelts; i ++) {
                apr_table_entry_t *e =
                    &((apr_table_entry_t*)((apr_table_elts(table))->elts))[i];
                APR_ARRAY_PUSH(retv, char*) = apr_psprintf(mp, "%s=%s",
                                                           e->key, e->val);
            }
        }
    }
    if (retv->nelts > 0) return q2_join(mp, retv, "&");
    return NULL;
}

static char* q2_array_pstrcat(apr_pool_t *mp,
                              apr_array_header_t *arr,
                              const char *sep)
{
    if (arr == NULL) return NULL;
    char *ret, *item;
    int rv, limit;
    apr_array_header_t *tmp;
    limit = arr->nelts - 1;
    tmp = apr_array_make(mp, 0, sizeof(void*));
    for (int i = 0; i < arr->nelts; i ++) {
        item = APR_ARRAY_IDX(arr, i, char*);
        if (item != NULL) {
            APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
            if (i < limit) APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sep);
        }
    }
    return apr_array_pstrcat(mp, tmp, 0);
}

static const char* q2_json_value(apr_pool_t *mp, const char *s)
{
    if (s == NULL) return NULL;
    switch (*s)
    {
    case '\0':
        return NULL;
    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return q2_is_float(s)
            ? s
            : apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, s, 1));
    case 't':
    case 'T':
        if (!strncmp(s, "true", 4))
            return apr_pstrdup(mp, "true");
    case 'f':
    case 'F':
        if (!strncmp(s, "false", 5))
            return apr_pstrdup(mp, "false");
    case 'n':
    case 'N':
        if (!strncmp(s, "null", 4) || !strncmp(s, "NULL", 4))
            return apr_pstrdup(mp, "null");
    default:
        return apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, s, 1));
    }
    return NULL;
}

static const char* q2_json_table(apr_pool_t *mp, apr_table_t *t)
{
    int len;
    apr_array_header_t *arr;
    if (t == NULL) return NULL;
    if ((len = (apr_table_elts(t))->nelts) <= 0) return NULL;
    if ((arr = apr_array_make(mp, len, sizeof(const char*))) == NULL)
        return NULL;
    for (int i = 0; i < len; i ++) {
        apr_table_entry_t *e =
            &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i];
        APR_ARRAY_PUSH(arr, const char*) =
            apr_psprintf(mp, "\"%s\":%s", (const char*)e->key,
                         q2_json_value(mp, (const char*)e->val));
    }
    return apr_pstrcat(mp, "{", apr_array_pstrcat(mp, arr, ','), "}", NULL);
}

static const char* q2_json_array(apr_pool_t *mp, apr_array_header_t *a, int tp)
{
    apr_array_header_t *arr = NULL;
    void *v = NULL;
    if (a == NULL || a->nelts <= 0) return NULL;
    arr = apr_array_make(mp, a->nelts, sizeof(const char*));
    for (int i = 0; i < a->nelts; i ++) {
        v = APR_ARRAY_IDX(a, i, void*);
        switch (tp)
        {
        case Q2_TABLE:
            APR_ARRAY_PUSH(arr, const char*) =
                q2_json_table(mp, (apr_table_t*)v);
            break;
        default:
            APR_ARRAY_PUSH(arr, const char*) =
                q2_json_value(mp, (const char*)v);
            break;
        }
    }
    return apr_pstrcat(mp, "[", apr_array_pstrcat(mp, arr, ','), "]", NULL);
}

static void q2_table_rprintf(void *ctx, apr_table_t *table)
{
    if (table != NULL) {
        if ((apr_table_elts(table))->nelts > 0) {
            for (int i = 0; i < (apr_table_elts(table))->nelts; i ++) {
                apr_table_entry_t *e =
                    &((apr_table_entry_t*)((apr_table_elts(table))->elts))[i];
                #ifdef _APMOD
                ap_rprintf((request_rec*)ctx, "%s: %s\n", e->key, e->val);
                #else
                printf("%s: %s\n", e->key, e->val);
                #endif
            }
        }
    }
}

static void q2_array_rprintf(void *ctx, apr_array_header_t *arr, int tp)
{
    if (arr != NULL && arr->nelts > 0) {
        for (int i = 0; i < arr->nelts; i ++) {
            switch(tp)
            {
            case Q2_STRING:
                #ifdef _APMOD
                ap_rprintf((request_rec*)ctx, "%s\n",
                           APR_ARRAY_IDX(arr, i, const char*));
                #else
                printf("%s\n", APR_ARRAY_IDX(arr, i, const char*));
                #endif
                break;
            case Q2_TABLE:
                q2_table_rprintf(ctx, APR_ARRAY_IDX(arr, i, apr_table_t*));
                break;
            }
        }
    }
}

static int q2_dbd_query(apr_pool_t *mp,
                        const apr_dbd_driver_t *drv,
                        apr_dbd_t *hd,
                        const char *sql,
                        int *err)
{
    int aff_rows = 0;
    if (sql == NULL) return -1;
    (*err) = apr_dbd_query(drv, hd, &aff_rows, sql);
    if (*err) return -1;
    return aff_rows;
}

static apr_array_header_t* q2_dbd_select(apr_pool_t *mp,
                                         const apr_dbd_driver_t *drv,
                                         apr_dbd_t *hd,
                                         const char *sql,
                                         int *err)
{
    apr_status_t rv;                //| status
    apr_dbd_results_t *res = NULL;  //| dbd resultset
    apr_dbd_row_t *row = NULL;      //| next row in the resultset
    apr_array_header_t *rset;       //| the recordset returned by the server
    apr_table_t *rec;               //| a recordset record
    int first_rec;
    int num_fields;
    const char *error;
    if (((*err) = apr_dbd_select(drv, mp, hd, &res, sql, 0))) return NULL;
    if (res == NULL) return NULL;
    if ((rv = apr_dbd_get_row(drv, mp, res, &row, -1)) == -1) return NULL;
    rset = NULL;
    first_rec = 1;
    while (rv != -1) {
        if (first_rec) {
            num_fields = apr_dbd_num_cols(drv, res);
            rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
            first_rec = 0;
        }
        rec = apr_table_make(mp, num_fields);
        for (int i = 0; i < num_fields; i ++) {
            const char *k = apr_dbd_get_name(drv, res, i);
            const char *v = apr_dbd_get_entry(drv, row, i);
            apr_table_setn(rec, apr_pstrdup(mp, k),
                           apr_pstrdup(mp, q2_is_empty_s(v) ? "NULL" : v));
        }
        APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
        rv = apr_dbd_get_row(drv, mp, res, &row, -1);
    }
    return rset;
}

static const char* q2_dbd_get_value(apr_array_header_t *rset,
                                    int i,
                                    const char *key)
{
    if (rset == NULL || rset->nelts <= 0 || i > (rset->nelts-1)) return NULL;
    apr_table_t* t = APR_ARRAY_IDX(rset, i, apr_table_t*);
    return apr_table_get(t, key);
}

static int q2_dbd_set_value(apr_array_header_t *rset, int i, const char *key,
                     const char *val)
{
    if (rset == NULL || rset->nelts <= 0 || i > (rset->nelts-1))
        return 1;
    apr_table_t* t = APR_ARRAY_IDX(rset, i, apr_table_t*);
    apr_table_setn(t, key, val);
    return 0;
}

static apr_table_t* q2_dbd_get_entry(apr_array_header_t *rset, int i)
{
    if (rset == NULL || rset->nelts <= 0 || i > (rset->nelts-1)) return NULL;
    return APR_ARRAY_IDX(rset, i, apr_table_t*);
}


#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_tb_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT table_name "
    "FROM INFORMATION_SCHEMA.tables WHERE table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_tb_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT table_name "
    "FROM INFORMATION_SCHEMA.tables WHERE table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_cl_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *cl,
                                            int *er)
{
    const char *pt =
    "SELECT column_name FROM INFORMATION_SCHEMA.columns "
    "WHERE table_name='%s' AND column_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb, cl);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_cl_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT ordinal_position,table_name,column_name,"
    "case when column_default is null then 'null' else column_default end "
    "as column_default,data_type,character_set_name,null as column_type,"
    "null as column_key,null as column_comment,0 as is_unsigned,"
    "0 as is_primary_key,0 as is_foreign_key,0 as is_auto_increment,"
    "case when is_nullable='YES' then 1 else 0 end as is_nullable,"
    "case when numeric_precision is null then 0 else 1 end as is_numeric,"
    "case when numeric_precision is null then 1 else 0 end as is_string,"
    "case when data_type='date' then 1 else 0 end as is_date,"
    "case when data_type='bit' then 1 else 0 end as is_boolean,"
    "null as column_options,null as referenced_schema,"
    "null as referenced_table,null as referenced_column,"
    "0 as is_referenced_pk_multi,null as referenced_pk "
    "FROM INFORMATION_SCHEMA.columns WHERE table_name='%s' "
    "ORDER BY ordinal_position ASC";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_pk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT k.column_name "
    "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k "
    "LEFT JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS c "
    "ON k.table_name = c.table_name "
    "AND k.table_schema = c.table_schema "
    "AND k.table_catalog = c.table_catalog "
    "AND k.constraint_catalog = c.constraint_catalog "
    "AND k.constraint_name = c.constraint_name "
    "WHERE c.constraint_type='PRIMARY KEY' AND "
    "k.constraint_catalog = DB_NAME() AND k.table_name = '%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_un_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_fk_tabs(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT k.table_name "
    "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k "
    "LEFT JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS c "
    "ON k.table_name = c.table_name "
    "AND k.table_schema = c.table_schema "
    "AND k.table_catalog = c.table_catalog "
    "AND k.constraint_catalog = c.constraint_catalog "
    "AND k.constraint_name = c.constraint_name "
    "LEFT JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc "
    "ON rc.constraint_schema = c.constraint_schema "
    "AND rc.constraint_catalog = c.constraint_catalog "
    "AND rc.constraint_name = c.constraint_name "
    "LEFT JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE ccu "
    "ON rc.unique_constraint_schema = ccu.constraint_schema "
    "AND rc.unique_constraint_catalog = ccu.constraint_catalog "
    "AND rc.unique_constraint_name = ccu.constraint_name "
    "WHERE k.constraint_catalog = DB_NAME() "
    "AND ccu.table_name = '%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_fk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt = "SELECT "
    "k.column_name, null as referenced_schema,"
    /*"CASE c.is_deferrable WHEN 'NO' THEN 0 ELSE 1 END 'is_deferrable', "*/
    /*"CASE c.initially_deferred WHEN 'NO' THEN 0 ELSE 1 END 'is_deferred', "*/
    /*"rc.match_option 'match_type', "*/
    /*"rc.update_rule 'on_update', "*/
    /*"rc.delete_rule 'on_delete', "*/
    "ccu.table_name 'referenced_table', "
    "ccu.column_name 'referenced_column' "
    /*"k.ordinal_position 'field_position' "*/
    "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE k "
    "LEFT JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS c "
    "ON k.table_name = c.table_name "
    "AND k.table_schema = c.table_schema "
    "AND k.table_catalog = c.table_catalog "
    "AND k.constraint_catalog = c.constraint_catalog "
    "AND k.constraint_name = c.constraint_name "
    "LEFT JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc "
    "ON rc.constraint_schema = c.constraint_schema "
    "AND rc.constraint_catalog = c.constraint_catalog "
    "AND rc.constraint_name = c.constraint_name "
    "LEFT JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE ccu "
    "ON rc.unique_constraint_schema = ccu.constraint_schema "
    "AND rc.unique_constraint_catalog = ccu.constraint_catalog "
    "AND rc.unique_constraint_name = ccu.constraint_name "
    "WHERE k.constraint_catalog = DB_NAME() "
    "AND k.table_name = '%s' "
    "AND c.constraint_type = 'FOREIGN KEY'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static apr_array_header_t* q2_mssql_id_last(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *pk,
                                            int *er)
{
    const char *pt = apr_pstrdup(mp, "SELECT SCOPE_IDENTITY() as last_id");
    return q2_dbd_select(mp, dbd_drv, dbd_hd, pt, er);
}
#endif

#if !defined (Q2DBD) || defined (MSSQL)
static const char* q2_mssql_getvers(apr_pool_t *mp,
                                    const apr_dbd_driver_t *dbd_drv,
                                    apr_dbd_t *dbd_hd,
                                    int *er)
{
    const char *pt = "SELECT SERVERPROPERTY('productversion') AS version";
    apr_array_header_t *res = q2_dbd_select(mp, dbd_drv, dbd_hd, pt, er);
    if (res != NULL) {
        apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
        if (t != NULL) return apr_table_get(t, "version");
    }
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_cl_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *cl,
                                            int *er)
{
    const char *pt =
    "SELECT column_name FROM INFORMATION_SCHEMA.columns "
    "WHERE table_name='%s' AND column_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb, cl);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_cl_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT ordinal_position as ordinal_position,"
    "table_name as table_name,"
    "column_name as column_name,"
    "(case when column_default is null then 'null' else column_default end) as column_default, "
    "data_type as data_type,"
    "(case when character_set_name is null then 'null' else character_set_name end) as character_set_name, "
    "column_type as column_type,"
    "(case when column_key is null then 'null' else column_key end) as column_key,"
    "(case when (column_comment is null or COLUMN_COMMENT like '') then 'null' else COLUMN_COMMENT end) as column_comment,"
    "(column_type LIKE '%%unsigned%%') as is_unsigned,"
    "0 as is_primary_key,"
    "0 as is_foreign_key,"
    "(extra LIKE 'auto_increment') as is_auto_increment,"
    "(is_nullable LIKE 'YES') as is_nullable,"
    "(!isnull(numeric_precision)) as is_numeric,"
    "(isnull(numeric_precision)) as is_string,"
    "(data_type LIKE 'date') as is_date,"
    "(column_type LIKE 'tinyint(1) unsigned') as is_boolean,"
    "'null' as column_options,"
    "'null' as referenced_schema,"
    "'null' as referenced_table,"
    "'null' as referenced_column,"
    "0 as is_referenced_pk_multi,"
    "'null' as referenced_pk "
    "FROM INFORMATION_SCHEMA.columns WHERE table_name='%s' "
    "ORDER BY ordinal_position ASC";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_pk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT c.column_name FROM "
    "INFORMATION_SCHEMA.columns AS c JOIN INFORMATION_SCHEMA.statistics AS s "
    "ON s.column_name=c.column_name AND s.table_schema=c.table_schema AND "
    "s.table_name=c.table_name WHERE !isnull(s.index_name) AND "
    "s.index_name LIKE 'PRIMARY' AND c.table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_un_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_fk_tabs(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt = 
    "SELECT table_name FROM INFORMATION_SCHEMA.key_column_usage "
    "WHERE referenced_table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_fk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT column_name,referenced_table_schema referenced_schema,"
    "referenced_table_name referenced_table,"
    "referenced_column_name referenced_column "
    "FROM INFORMATION_SCHEMA.key_column_usage "
    "WHERE referenced_column_name IS NOT NULL AND table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static apr_array_header_t* q2_mysql_id_last(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *pk,
                                            int *er)
{
    const char *sql = apr_pstrdup(mp, "SELECT last_insert_id() as last_id");
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (MYSQL)
static const char* q2_mysql_getvers(apr_pool_t *mp,
                                    const apr_dbd_driver_t *dbd_drv,
                                    apr_dbd_t *dbd_hd,
                                    int *er)
{
    const char *sql = apr_pstrdup(mp, "SELECT version() version");
    apr_array_header_t *res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res != NULL) {
        apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
        if (t != NULL) return apr_table_get(t, "version");
    }
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_tb_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT table_name FROM INFORMATION_SCHEMA.tables WHERE table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_cl_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *cl,
                                            int *er)
{
    const char *pt =
    "SELECT column_name FROM INFORMATION_SCHEMA.columns "
    "WHERE table_name='%s' AND column_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb, cl);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_cl_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT ordinal_position,table_name,column_name,column_default,data_type,"
    "character_set_name,null AS column_type,null AS column_key,"
    "null AS column_comment,0 AS is_date,0 AS is_unsigned,0 AS is_primary_key,"
    "0 AS is_foreign_key,"
    "CASE WHEN column_default LIKE 'nextval%%' THEN 1 ELSE 0 END "
    "AS is_auto_increment,"
    "CASE WHEN is_nullable='NO' THEN 0 ELSE 1 END AS is_nullable,"
    "CASE WHEN numeric_precision is not null THEN 1 ELSE 0 END AS is_numeric,"
    "CASE WHEN numeric_precision is null THEN 1 ELSE 0 END AS is_string,"
    "CASE WHEN data_type='boolean' THEN 1 ELSE 0 END AS is_boolean,"
    "null AS column_options,null AS referenced_schema,null AS referenced_table,"
    "null AS referenced_column,0 AS is_referenced_pk_multi,null AS referenced_pk "
    "FROM INFORMATION_SCHEMA.columns WHERE table_name='%s' "
    "ORDER BY ordinal_position ASC";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_pk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT kcu.column_name,1 AS is_primary_key "
    "FROM INFORMATION_SCHEMA.table_constraints tc LEFT JOIN "
    "INFORMATION_SCHEMA.key_column_usage kcu ON "
    "kcu.table_catalog=tc.table_catalog AND "
    "kcu.table_schema=tc.table_schema AND kcu.table_name=tc.table_name AND "
    "kcu.constraint_name=tc.constraint_name "
    "WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_un_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT cu.column_name,"
    "CASE WHEN cc.check_clause=concat('((',cu.column_name::text,'>=0))') "
    "THEN 1 ELSE 0 END AS is_unsigned "
    "FROM INFORMATION_SCHEMA.constraint_column_usage AS cu NATURAL JOIN "
    "INFORMATION_SCHEMA.check_constraints AS cc WHERE cu.table_name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_fk_tabs(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT table_name AS name,count(table_name) AS count FROM "
    "INFORMATION_SCHEMA.table_constraints WHERE constraint_type='FOREIGN KEY' "
    "GROUP BY table_name ORDER BY count DESC";
    return q2_dbd_select(mp, dbd_drv, dbd_hd, pt, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_fk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT k1.column_name,k2.table_schema referenced_schema,"
    "k2.table_name referenced_table,k2.column_name referenced_column "
    "FROM INFORMATION_SCHEMA.key_column_usage k1 JOIN "
    "INFORMATION_SCHEMA.referential_constraints fk "
    "USING (constraint_schema,constraint_name) JOIN "
    "INFORMATION_SCHEMA.key_column_usage k2 ON "
    "k2.constraint_schema=fk.unique_constraint_schema AND "
    "k2.constraint_name=fk.unique_constraint_name AND "
    "k2.ordinal_position=k1.position_in_unique_constraint "
    "WHERE k1.table_name='%s' AND k2.table_name!='%s'";
    const char *sql = apr_psprintf(mp, pt, tb, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static apr_array_header_t* q2_pgsql_id_last(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *pk,
                                            int *er)
{
    const char *sql = apr_psprintf(mp, "SELECT currval('%s_%s_seq')", tb, pk);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (PGSQL)
static const char* q2_pgsql_getvers(apr_pool_t *mp,
                                    const apr_dbd_driver_t *dbd_drv,
                                    apr_dbd_t *dbd_hd,
                                    int *er)
{
    const char *sql = apr_pstrdup(mp, "SELECT version() as version");
    apr_array_header_t *res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res != NULL && res->nelts > 0) {
        apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
        if (t != NULL) return apr_table_get(t, "version");
    }
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_tb_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
    apr_array_header_t *res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res == NULL) return NULL;
    apr_table_t *tab = APR_ARRAY_IDX(res, 0, apr_table_t*);
    apr_table_set(tab, "table_name", tb);
    return res;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_cl_name(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *cl,
                                            int *er)
{
    const char *sql, *col;
    apr_array_header_t *res;
    apr_table_t *tab;
    sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
    if (sql == NULL) return NULL;
    res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res == NULL || res->nelts <= 0) return NULL;
    for (int i = 0; i < res->nelts; i ++) {
        tab = APR_ARRAY_IDX(res, i, apr_table_t*);
        col = apr_table_get(tab, "name");
        if (col == NULL) continue;
        if (strcmp(col, cl) == 0) return res;
    }
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_cl_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT t.cid+1 ordinal_position,'%s' table_name,t.name column_name,"
    "t.dflt_value column_default,t.type data_type,e.encoding character_set_name,"
    "t.type column_type,null column_key,null column_comment,0 is_unsigned,"
    "t.pk is_primary_key,0 is_foreign_key,"
    "CASE WHEN ((SELECT 1 FROM sqlite_master AS m WHERE "
    "m.'name'='%s' AND lower(sql) LIKE '%%autoincrement%%')=1) AND (t.'pk'=1) "
    "THEN '1' ELSE '0' END is_auto_increment,"
    "CASE WHEN t.'notnull'='0' THEN '0' ELSE '1' END is_nullable,"
    "CASE WHEN lower(t.'type')='integer' OR lower(t.'type')='numeric' OR "
    "lower(t.'type')='real' THEN '1' ELSE '0' END is_numeric,"
    "CASE WHEN lower(t.'type')='text' THEN '1' ELSE '0' END is_string,"
    "0 as is_date,0 as is_boolean,null column_options,null referenced_schema,"
    "null referenced_table,null referenced_column,0 is_referenced_pk_multi,"
    "null referenced_pk FROM "
    "pragma_table_info('%s') AS t,pragma_encoding AS e,"
    "sqlite_master AS m WHERE m.name='%s'";
    const char *sql = apr_psprintf(mp, pt, tb, tb, tb, tb);
    if (sql == NULL) return NULL;
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_pk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *sql, *attrib, *encoding = NULL;
    apr_array_header_t *res, *retv;
    apr_table_t *tab;
    sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
    if (sql == NULL) return NULL;
    res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res == NULL || res->nelts <= 0) return NULL;
    retv = apr_array_make(mp, 1, sizeof(apr_table_t*));
    if (retv == NULL) return NULL;
    for (int i = 0; i < res->nelts; i ++) {
        tab = APR_ARRAY_IDX(res, i, apr_table_t*);
        if ((attrib = apr_table_get(tab, "pk")) == NULL) continue;
        if (atoi(attrib)) {
            if ((attrib = apr_table_get(tab, "name")) == NULL) continue;
            apr_table_set(tab, "column_name", attrib);
            apr_table_unset(tab, "cid");
            apr_table_unset(tab, "name");
            apr_table_unset(tab, "type");
            apr_table_unset(tab, "notnull");
            apr_table_unset(tab, "dflt_value");
            apr_table_unset(tab, "pk");
            APR_ARRAY_PUSH(retv, apr_table_t*) = tab;
        }
    }
    return retv;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_un_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    return NULL;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_fk_tabs(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *pt =
    "SELECT m.name table_name FROM sqlite_master m "
    "JOIN pragma_foreign_key_list(m.name) p ON m.name!=p.'table' "
    "AND p.'table'='%s' WHERE m.type='table' ORDER BY m.name";
    const char *sql = apr_psprintf(mp, pt, tb);
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_fk_attr(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            int *er)
{
    const char *sql, *attrib;
    apr_array_header_t *res;
    apr_table_t *tab;
    sql = apr_psprintf(mp, "PRAGMA foreign_key_list(%s)", tb);
    res = sql != NULL ? q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er) : NULL;
    if (res == NULL || res->nelts <= 0) return NULL;
    for (int i = 0; i < res->nelts; i++) {
        tab = APR_ARRAY_IDX(res, i, apr_table_t*);
        if (tab == NULL || (apr_table_elts(tab))->nelts <= 0) continue;
        if((attrib = apr_table_get(tab, "from")) == NULL) continue;
        apr_table_set(tab, "column_name", attrib);
        apr_table_set(tab, "is_foreign_key", "1");
        apr_table_set(tab, "referenced_schema", "null");
        if ((attrib = apr_table_get(tab, "table")) == NULL) continue;
        apr_table_set(tab, "referenced_table", attrib);
        if ((attrib = apr_table_get(tab, "to")) == NULL) continue;
        apr_table_set(tab, "referenced_column", attrib);
        apr_table_unset(tab, "id");
        apr_table_unset(tab, "seq");
        apr_table_unset(tab, "table");
        apr_table_unset(tab, "from");
        apr_table_unset(tab, "to");
        apr_table_unset(tab, "table");
        apr_table_unset(tab, "on_update");
        apr_table_unset(tab, "on_delete");
        apr_table_unset(tab, "match");
    }
    return res;
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static apr_array_header_t* q2_sqlt3_id_last(apr_pool_t *mp,
                                            const apr_dbd_driver_t *dbd_drv,
                                            apr_dbd_t *dbd_hd,
                                            const char *tb,
                                            const char *pk,
                                            int *er)
{
    const char *sql = apr_pstrdup(mp, "SELECT last_insert_rowid()");
    return q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
}
#endif

#if !defined (Q2DBD) || defined (SQLITE3)
static const char* q2_sqlt3_getvers(apr_pool_t *mp,
                                    const apr_dbd_driver_t *dbd_drv,
                                    apr_dbd_t *dbd_hd,
                                    int *er)
{
    const char *sql = apr_pstrdup(mp, "SELECT sqlite_version() as version");
    apr_array_header_t *res = q2_dbd_select(mp, dbd_drv, dbd_hd, sql, er);
    if (res != NULL && res->nelts > 0) {
        apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
        if (t != NULL) return apr_table_get(t, "version");
    }
    return NULL;
}
#endif

static int q2_uri_get_pages(apr_pool_t *mp, apr_array_header_t *apr_uri_t)
{
    int page;
    const char *next, *page_s;
    if (apr_uri_t->nelts < 5) return 0;
    page_s = APR_ARRAY_IDX(apr_uri_t, apr_uri_t->nelts-1, const char*);
    if (page_s == NULL) return 0;
    if (q2_is_integer(page_s)) {
        page = atoi(page_s);
        if (page > 0) {
            next = APR_ARRAY_IDX(apr_uri_t, apr_uri_t->nelts-2, const char*);
            if (strncasecmp(next, "next", 4) == 0) {
            }
        }
    }
    return 0;
}

static apr_array_header_t* q2_uri_get_tabs(apr_pool_t *mp,
                                           apr_array_header_t *apr_uri_t)
{
    const char *path_i = NULL;
    apr_array_header_t *retv = NULL;
    if (apr_uri_t == NULL || apr_uri_t->nelts < 3) return NULL;
    for (int i = 2; i < apr_uri_t->nelts; i ++) {
        path_i = APR_ARRAY_IDX(apr_uri_t, i, const char*);
        if (path_i == NULL) continue;
        if (q2_is_integer(path_i)) continue;
        if ((i-1) % 2 == 0) continue;
        if (retv == NULL) {
            if ((retv = apr_array_make(mp, 0, sizeof(const char*))) == NULL)
                return NULL;
        }
        APR_ARRAY_PUSH(retv, const char*) = path_i;
    }
    return retv;
}

static apr_array_header_t* q2_uri_get_keys(apr_pool_t *mp,
                                           apr_array_header_t *apr_uri_t)
{
    const char *path_i = NULL;
    apr_array_header_t *retv = NULL;
    if (apr_uri_t == NULL || apr_uri_t->nelts < 3) return NULL;
    for (int i = 2; i < apr_uri_t->nelts; i ++) {
        path_i = APR_ARRAY_IDX(apr_uri_t, i, const char*);
        if (path_i == NULL) continue;
        if ((i-1) % 2 == 0) {
            //if (!q2_is_integer(path_i)) continue;
            if (retv == NULL) {
                if ((retv = apr_array_make(mp, 0, sizeof(const char*))) == NULL)
                    return NULL;
            }
            APR_ARRAY_PUSH(retv, const char*) = path_i;
        }
    }
    return retv;
}

static const char* q2_ischema_pgsql_get_target_table_mm(q2_t *q2)
{
    int er, tab_n_fk, count;
    const char *sql, *mul_fk_tab_name, *rtname;
    apr_array_header_t *mul_fk_tabs, *ref_tabs;
    mul_fk_tabs = q2->fk_tabs_fn(q2->pool, q2->dbd_driver,
                                 q2->dbd_handle, NULL, &er);
    if (er) q2_log_error(q2, "%s",
                         apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
    if (mul_fk_tabs == NULL) return NULL;
    if (mul_fk_tabs->nelts > 0) {
        for (int i = 0; i < mul_fk_tabs->nelts; i ++) {
            tab_n_fk = atoi(q2_dbd_get_value(mul_fk_tabs, i, "count"));
            if (tab_n_fk < 2) continue;
            mul_fk_tab_name = q2_dbd_get_value(mul_fk_tabs, i, "name");
            ref_tabs = q2->fk_attr_fn(q2->pool, q2->dbd_driver,
                                      q2->dbd_handle, mul_fk_tab_name, &er);
            if (er) q2_log_error(q2, "%s",
                                 apr_dbd_error(q2->dbd_driver,
                                               q2->dbd_handle, er));
            if (ref_tabs == NULL) return NULL;
            if (ref_tabs->nelts < q2->uri_tables->nelts) continue;
            count = 0;
            for (int j = 0; j < ref_tabs->nelts; j ++) {
                rtname = q2_dbd_get_value(ref_tabs, j, "referenced_table");
                for (int k = 0; k < q2->uri_tables->nelts; k ++) {
                    int cmp = strcmp(rtname, APR_ARRAY_IDX(q2->uri_tables,
                                                           k, const char*));
                    if (cmp == 0) count ++;
                }
            }
            if (count == q2->uri_tables->nelts) return mul_fk_tab_name;
        }
    }
    return NULL;
}

static const char* q2_ischema_get_target_table(q2_t *q2, int rel)
{
    int er, count;
    const char *sql, *sql_pk, *sql_fk, *table, *tname, *rtname, *cname;
    apr_array_header_t *rset, *rset_pk, *rset_fk, *rset_;
    if (q2->uri_tables == NULL) return NULL;
    if (rel == Q2_RL_11REL) {
        if (q2->uri_tables->nelts <= 1) return NULL;
        table = APR_ARRAY_IDX(q2->uri_tables,
                              q2->uri_tables->nelts-1, const char*);
        if (table == NULL) return NULL;
        sql_pk = NULL;
        sql_fk = NULL;
        rset_pk = q2->pk_attr_fn(q2->pool, q2->dbd_driver,
                                     q2->dbd_handle, table, &er);
        if (rset_pk == NULL) {
            if (er) q2_log_error(q2, "%s",
                                 apr_dbd_error(q2->dbd_driver,
                                               q2->dbd_handle, er));
            return NULL;
        }
        if (rset_pk->nelts <= 0) return NULL;
        rset_fk = q2->fk_attr_fn(q2->pool, q2->dbd_driver,
                                     q2->dbd_handle, table, &er);
        if (er) q2_log_error(q2, "%s",
                             apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        if (rset_fk == NULL) return NULL;
        if (rset_fk->nelts <= 0) return NULL;
        count = 0;
        for (int i = 0; i < rset_pk->nelts; i ++) {
            for (int j = 0; j < rset_fk->nelts; j ++) {
                const char *pk_name = q2_dbd_get_value(rset_pk, i, "column_name");
                const char *fk_name = q2_dbd_get_value(rset_fk, i, "column_name");
                if (strcmp(pk_name, fk_name) == 0) count ++;
            }
        }
        if (count != rset_pk->nelts || count != rset_fk->nelts) return NULL;
        count = 0;
        for (int i = 0; i < rset_fk->nelts; i ++) {
            const char *dbs_tab;
            dbs_tab = q2_dbd_get_value(rset_fk, i, "referenced_table");
            for (int j = 0; j < q2->uri_tables->nelts-1; j ++) {
                const char *uri_tab;
                uri_tab = APR_ARRAY_IDX(q2->uri_tables, j, const char*);
                if (strcmp(dbs_tab, uri_tab) == 0) count ++;
            }
        }
        if (count != rset_fk->nelts) return NULL;
        return apr_pstrdup(q2->pool, table);
    }
    else if (rel == Q2_RL_1MREL) {
        if (q2->uri_tables->nelts <= 1) return NULL;
        table = APR_ARRAY_IDX(q2->uri_tables,
                              q2->uri_tables->nelts-1, const char*);
        if (table == NULL) return NULL;
        sql = NULL;
        rset = q2->fk_attr_fn(q2->pool, q2->dbd_driver,
                                  q2->dbd_handle, table, &er);
        if (er) q2_log_error(q2, "%s",
                             apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        if (rset == NULL) return NULL;
        count = 0;
        for (int i = 0; i < rset->nelts; i ++) {
            rtname = q2_dbd_get_value(rset, i, "referenced_table");
            for (int j = 0; j < q2->uri_tables->nelts; j ++) {
                if (strcmp(rtname, table) != 0) {
                    if (strcmp(rtname, APR_ARRAY_IDX(
                            q2->uri_tables, j, const char*)) == 0)
                        count ++;
                }
            }
        }
        if (count != q2->uri_tables->nelts-1) return NULL;
        return apr_pstrdup(q2->pool, table);
    }
    else if (rel == Q2_RL_MMREL) {
        if (q2->uri_tables->nelts <= 1) return NULL;


        if (q2->dbd_server_type == Q2_DBD_PGSQL)
            return q2_ischema_pgsql_get_target_table_mm(q2);

        table = APR_ARRAY_IDX(q2->uri_tables,
                              q2->uri_tables->nelts-1, const char*);
        if (table == NULL) return NULL;
        rset = q2->fk_tabs_fn(q2->pool, q2->dbd_driver,
                                  q2->dbd_handle, table, &er);
        if (er) q2_log_error(q2, "%s",
                             apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        if (rset == NULL) return NULL;
        for (int i = 0; i < rset->nelts; i ++) {
            tname = q2_dbd_get_value(rset, i, "table_name");
            rset_ = q2->fk_attr_fn(q2->pool, q2->dbd_driver,
                                       q2->dbd_handle, tname, &er);
            if (er) q2_log_error(q2, "%s",
                                 apr_dbd_error(q2->dbd_driver,
                                               q2->dbd_handle, er));
            if (rset == NULL) continue;
            if (rset_->nelts != q2->uri_tables->nelts) continue;
            count = 0;
            for (int j = 0; j < rset_->nelts; j ++) {
                rtname = q2_dbd_get_value(rset_, j, "referenced_table");
                for (int k = 0; k < q2->uri_tables->nelts; k ++) {
                    if (strcmp(rtname, APR_ARRAY_IDX(
                            q2->uri_tables, k, const char*)) == 0)
                        count ++;
                }
            }
            if (count == q2->uri_tables->nelts)
                return apr_pstrdup(q2->pool, tname);
        }
    }
    else {
        if (q2->uri_tables->nelts <= 1) {
            rset = q2->tb_name_fn(q2->pool, q2->dbd_driver, q2->dbd_handle,
                                      APR_ARRAY_IDX(q2->uri_tables,
                                                    0, const char*), &er);
            if (rset == NULL) {
                q2_log_error(q2, "%s",
                             er ? apr_dbd_error(q2->dbd_driver,
                                                q2->dbd_handle, er)
                                : "Invalid table name");
                return NULL;
            }
            return q2_dbd_get_value(rset, 0, "table_name");
        }
        table = APR_ARRAY_IDX(q2->uri_tables, 0, const char*);
        if (table == NULL) return NULL;
        cname = APR_ARRAY_IDX(q2->uri_tables, 1, const char*);
        if (cname == NULL) return NULL;
        rset = q2->tb_name_fn(q2->pool, q2->dbd_driver,
                                  q2->dbd_handle, table, &er);
        if (rset == NULL) {
            if (er) q2_log_error(q2, "%s",
                                 apr_dbd_error(q2->dbd_driver,
                                               q2->dbd_handle, er));
            return NULL;
        }
        tname = q2_dbd_get_value(rset, 0, "table_name");
        rset = q2->cl_name_fn(q2->pool, q2->dbd_driver,
                                  q2->dbd_handle, tname, cname, &er);
        if (rset == NULL) {
            if (er) q2_log_error(q2, "%s",
                                 apr_dbd_error(q2->dbd_driver,
                                               q2->dbd_handle, er));
            return NULL;
        }
        return apr_pstrdup(q2->pool, tname);
    }
    return NULL;
}
static apr_array_header_t* q2_ischema_get_col_attrs(q2_t *q2, const char *tab)
{
    int er = 0;
    apr_array_header_t *rset;
    rset = q2->cl_attr_fn(q2->pool, q2->dbd_driver, q2->dbd_handle, tab, &er);
    if (er) {
        q2_log_error(q2, "%s",
                     apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        return NULL;
    }
    return rset;
}

static apr_array_header_t* q2_ischema_get_pk_attrs(q2_t *q2, const char *tab)
{
    int er = 0;
    apr_array_header_t *rset;
    rset = q2->pk_attr_fn(q2->pool, q2->dbd_driver, q2->dbd_handle, tab, &er);
    if (er) {
        q2_log_error(q2, "%s",
                     apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        return NULL;
    }
    return rset;
}

static apr_array_header_t* q2_ischema_get_unsig_attrs(q2_t *q2, const char *tab)
{
    int er = 0;
    apr_array_header_t *rset;
    if (q2->dbd_server_type == Q2_DBD_MYSQL) return NULL;
    rset = q2->un_attr_fn(q2->pool, q2->dbd_driver, q2->dbd_handle, tab, &er);
    if (er) q2_log_error(q2, "%s",
                         apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
    return rset;
}

static apr_array_header_t* q2_ischema_get_refs_attrs(q2_t *q2, const char *tab)
{
    int er = 0;
    apr_array_header_t *rset;
    rset = q2->fk_attr_fn(q2->pool, q2->dbd_driver, q2->dbd_handle, tab, &er);
    if (er) q2_log_error(q2, "%s",
                         apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
    return rset;
}

static int q2_ischema_update_attrs(q2_t *q2)
{
    const char *c_name, *c_pk_name, *c_uns_name, *c_rf_name;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        if (q2->pk_attrs != NULL && q2->pk_attrs->nelts > 0) {
            for (int j = 0; j < q2->pk_attrs->nelts; j ++) {
                c_pk_name = q2_dbd_get_value(q2->pk_attrs,
                                             j, "column_name");
                if (c_pk_name == NULL) continue;
                if (strcmp(c_name, c_pk_name) != 0) continue;
                q2_dbd_set_value(q2->attributes, i, "is_primary_key", "1");
            }
        }
        if (q2->unsigned_attrs != NULL &&
            q2->unsigned_attrs->nelts > 0) {
            for (int j = 0; j < q2->unsigned_attrs->nelts; j ++) {
                c_uns_name = q2_dbd_get_value(q2->unsigned_attrs,
                                              j, "column_name");
                if (c_uns_name == NULL) continue;
                if (strcmp(c_name, c_uns_name) != 0) continue;
                q2_dbd_set_value(q2->attributes, i, "is_unsigned", "1");
            }
        }
        if (q2->refs_attrs != NULL && q2->refs_attrs->nelts > 0) {
            for (int j = 0; j < q2->refs_attrs->nelts; j ++) {
                c_rf_name = q2_dbd_get_value(q2->refs_attrs,
                                             j, "column_name");
                if (c_rf_name == NULL) continue;
                if (strcmp(c_name, c_rf_name) != 0) continue;
                q2_dbd_set_value(q2->attributes, i, "is_foreign_key", "1");
                q2_dbd_set_value(q2->attributes, i, "referenced_schema",
                                 q2_dbd_get_value(q2->refs_attrs,
                                 j, "referenced_schema"));
                q2_dbd_set_value(q2->attributes, i, "referenced_table",
                                 q2_dbd_get_value(q2->refs_attrs,
                                 j, "referenced_table"));
                q2_dbd_set_value(q2->attributes, i, "referenced_column",
                                 q2_dbd_get_value(q2->refs_attrs,
                                 j, "referenced_column"));
                const char *rt = q2_dbd_get_value(q2->refs_attrs,
                                                  j, "referenced_table");
                apr_array_header_t *rk = q2_ischema_get_pk_attrs(q2, rt);
                if(rk == NULL || rk->nelts <= 0) continue;
                if (rk->nelts <= 1) {
                    q2_dbd_set_value(q2->attributes, i, "referenced_pk",
                                     q2_dbd_get_value(rk, 0, "column_name"));
                    continue;
                }
                apr_array_header_t *rk_names =
                    apr_array_make(q2->pool, rk->nelts, sizeof(const char*));
                for (int k = 0; k < rk->nelts; k ++)
                    APR_ARRAY_PUSH(rk_names, const char*) =
                        q2_dbd_get_value(rk, k, "column_name");
                q2_dbd_set_value(q2->attributes, i, "referenced_pk",
                                 apr_array_pstrcat(q2->pool, rk_names, ','));
                q2_dbd_set_value(q2->attributes, i,
                                 "is_referenced_pk_multi", "1");
            }
        }
    }
    return 0;
}

static int q2_ischema_update_options_attr(q2_t*q2)
{
    int fk, ref_pk_multi, k;
    const char *ref_schema, *ref_table, *ref_column, *ref_pk, *ref_pk_arr_item;
    apr_array_header_t *qs_cmps, *ref_pk_arr;
    char *qs, *col_opt_uri;
    if (q2->attributes == NULL || q2->attributes->nelts <= 0) return 1;
    qs_cmps = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        ref_schema = q2_dbd_get_value(q2->attributes, i, "referenced_schema");
        ref_table = q2_dbd_get_value(q2->attributes, i, "referenced_table");
        ref_column = q2_dbd_get_value(q2->attributes, i, "referenced_column");
        ref_pk = q2_dbd_get_value(q2->attributes, i, "referenced_pk");
        fk  = atoi(q2_dbd_get_value(q2->attributes, i, "is_foreign_key"));
        ref_pk_multi = atoi(q2_dbd_get_value(q2->attributes,
                                             i, "is_referenced_pk_multi"));
        if (q2->r_others != NULL &&
            (apr_table_elts(q2->r_others))->nelts > 0 &&
            fk &&
            ref_pk_multi &&
            strcmp(ref_pk, "null") &&
            strcmp(ref_schema, "null") &&
            strcmp(ref_table, "null") &&
            strcmp(ref_column, "null")) {
            qs_cmps = apr_array_make(q2->pool, 0, sizeof(void*));
            ref_pk_arr = q2_split(q2->pool, (char*)ref_pk, ",");
            k = 0;
            for (int m = 0; m < (apr_table_elts(q2->r_others))->nelts; m ++) {
                apr_table_entry_t *e =
                    &((apr_table_entry_t*)(
                            (apr_table_elts(q2->r_others))->elts))[m];
                for (int n = 0; n < ref_pk_arr->nelts; n ++) {
                    ref_pk_arr_item = APR_ARRAY_IDX(ref_pk_arr, n, const char*);
                    if (strcmp(e->key, ref_pk_arr_item) == 0 &&
                        strcmp(e->key, ref_column)) {
                        APR_ARRAY_PUSH(qs_cmps, const char*) =
                            apr_pstrcat(q2->pool, ref_pk_arr_item,
                                        "=", e->val, NULL);
                        k ++;
                    }
                }
            }
            if (k > 0) {
                qs = apr_array_pstrcat(q2->pool, qs_cmps, '&');
                col_opt_uri = apr_pstrcat(q2->pool, "/", ref_table,
                                          "/", ref_column, "?", qs, NULL);
                if (col_opt_uri == NULL) return 1;
                q2_dbd_set_value(q2->attributes, i,
                                 "column_options", col_opt_uri);
            }
        } 
        else if (fk &&
                 strcmp(ref_schema, "null") &&
                 strcmp(ref_table, "null") &&
                 strcmp(ref_column, "null")) {
            col_opt_uri = apr_pstrcat(q2->pool, "/",
                                      ref_table, "/", ref_column, NULL);
            if (col_opt_uri == NULL) return 1;
            q2_dbd_set_value(q2->attributes, i, "column_options", col_opt_uri);
        }
    }
    return 0;
}

static const char* q2_ischema_get_last_id(q2_t *q2)
{
    apr_array_header_t *res = NULL;
    apr_table_t *tab;
    if (q2->dbd_server_type == Q2_DBD_MYSQL) {
        res = q2->id_last_fn(q2->pool, q2->dbd_driver, q2->dbd_handle, NULL,
                             NULL, &q2->error);
    } else if (q2->dbd_server_type == Q2_DBD_PGSQL) {
        res = NULL;
    } else if (q2->dbd_server_type == Q2_DBD_SQLT3) {
        res = NULL;
    } else if (q2->dbd_server_type == Q2_DBD_MSSQL) {
        res = NULL;
    }
    if (res == NULL || res->nelts <= 0) return NULL;
    tab = APR_ARRAY_IDX(res, 0, apr_table_t*);
    return apr_table_get(tab, "last_id");
}

static apr_table_t* q2_request_parse_params(q2_t* q2)
{
    int err;
    const char *ckey, *cval;
    apr_table_t *r_params_merge, *retv;
    if (q2->attributes == NULL || q2->request_params == NULL) return NULL;
    if ((retv = apr_table_make(q2->pool, 0)) == NULL) return NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        ckey = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (ckey == NULL) continue;
        cval = apr_table_get(q2->request_params, ckey);
        if (cval == NULL) continue;
        apr_table_set(retv, ckey, cval);
    }
    if (q2->tab_relation != Q2_RL_MMREL) return retv;
    if (q2->uri_tables == NULL) return retv;
    if (q2->uri_tables->nelts <= 0) return retv;
    for (int i = 0; i < q2->uri_tables->nelts; i ++) {
        const char *t_name = APR_ARRAY_IDX(q2->uri_tables, i, const char*);
        if (strcmp(t_name, q2->table) == 0) continue;
        apr_array_header_t *col_attrs_merge =
            q2_ischema_get_col_attrs(q2, t_name);
        if (col_attrs_merge == NULL) continue;
        r_params_merge = apr_table_make(q2->pool, 0);
        if (r_params_merge == NULL) {
            q2_log_error(q2, "%s", "apr_table_make failed");
            return NULL;
        }
        for (int j = 0; j < col_attrs_merge->nelts; j ++) {
            ckey = q2_dbd_get_value(col_attrs_merge, j, "column_name");
            if (ckey == NULL) continue;
            cval = apr_table_get(q2->request_params, ckey);
            if (cval == NULL) continue;
            apr_table_set(retv, ckey, cval);
        }
    }
    return retv;
}

static const char* q2_sql_encode_value(q2_t *q2,
                                       apr_table_t *attrs,
                                       const char *val)
{
    unsigned char is_mysql = 0, is_numeric = 0, is_date = 0;
    size_t value_len = 0;
    const char *dbd_driver_name, *character_set_name;
    char *tmp_v;
    if (val == NULL) return NULL;
    is_mysql = q2->dbd_server_type == Q2_DBD_MYSQL;
    is_numeric = (unsigned char)atoi(apr_table_get(attrs, "is_numeric"));
    is_date = (unsigned char)atoi(apr_table_get(attrs, "is_date"));
    character_set_name = NULL;
    if (!is_numeric && !is_date)
        character_set_name = apr_table_get(attrs, "character_set_name");
    tmp_v = apr_pstrdup(q2->pool, val);
    value_len = strlen(val);
    for (int i = 0; i < value_len; i ++)
        if (tmp_v[i] == '*') tmp_v[i] = '%';
    if (is_numeric || q2_is_null_s(tmp_v))
        return apr_psprintf(q2->pool, "%s", tmp_v);
    return apr_psprintf(q2->pool,
                        is_mysql && character_set_name != NULL
                            ? "_%s'%s'"
                            : "%s'%s'",
                        is_mysql
                            ? (character_set_name == NULL
                                ? ""
                                : character_set_name)
                            : "",
                        apr_dbd_escape(q2->dbd_driver,
                                       q2->pool, tmp_v, q2->dbd_handle));
}

static const char* q2_sql_parse_value(q2_t *q2, apr_table_t *attrs,
                                      const char *key, const char *val,
                                      apr_array_header_t **order_by)
{
    unsigned char is_numeric = 0, is_date = 0;
    size_t value_len = 0;
    const char *value_v = NULL, *parsed_v = NULL, *encoded_v = NULL;
    const char *character_set_name = NULL, *filter = NULL;
    apr_array_header_t *splitted_v = NULL, *range_toks = NULL, *set_toks = NULL;
    char ptt[32] = {0};
    if (attrs == NULL || key == NULL || val == NULL) return NULL;
    is_numeric = (unsigned char)atoi(apr_table_get(attrs, "is_numeric"));
    is_date = (unsigned char)atoi(apr_table_get(attrs, "is_date"));
    if (!is_numeric && !is_date)
        character_set_name = apr_table_get(attrs, "character_set_name");
    splitted_v = q2_split(q2->pool, (char*)val, ":");
    if (splitted_v == NULL) return NULL;
    if (splitted_v->nelts > 1) {
        filter = APR_ARRAY_IDX(splitted_v, 0, const char*);
        value_v = APR_ARRAY_IDX(splitted_v, 1, const char*);
    } else {
        value_v = APR_ARRAY_IDX(splitted_v, 0, char*);
    }
    if (filter != NULL) {
        if (q2_in_string(filter, 'a')) {
            if ((*order_by) == NULL)
                (*order_by) = apr_array_make(q2->pool, 1, sizeof(const char*));
            APR_ARRAY_PUSH((*order_by), const char*) =
                apr_pstrcat(q2->pool, key, " ASC", NULL);
        } else if (q2_in_string(filter, 'd')) {
            if ((*order_by) == NULL)
                (*order_by) = apr_array_make(q2->pool, 1, sizeof(const char*));
            APR_ARRAY_PUSH((*order_by), const char*) =
                apr_pstrcat(q2->pool, key, " DESC", NULL);
        } else if (q2_in_string(filter, 'A')) {
            if ((*order_by) == NULL)
                (*order_by) = apr_array_make(q2->pool, 1, sizeof(const char*));
            APR_ARRAY_PUSH((*order_by), const char*) =
                apr_pstrcat(q2->pool, "CAST(" , key, " AS UNSIGNED) ASC, ",
                            key, " ASC", NULL);
        } else if (q2_in_string(filter, 'D')) {
            if ((*order_by) == NULL)
                (*order_by) = apr_array_make(q2->pool, 1, sizeof(const char*));
            APR_ARRAY_PUSH((*order_by), const char*) =
                apr_pstrcat(q2->pool, "CAST(" , key, " AS UNSIGNED) DESC, ",
                            key, " DESC", NULL);
        }
        if (q2_in_string(filter, 'r')) {
            const char *from = NULL, *to = NULL;
            range_toks = q2_split(q2->pool, (char*)value_v, ",");
            if (range_toks->nelts == 2) {
                from = APR_ARRAY_IDX(range_toks, 0, const char*);
                to = APR_ARRAY_IDX(range_toks, 1, const char*);
                strcpy(ptt, "(%s>=%s) AND (%s<=%s)");
                parsed_v = apr_psprintf(q2->pool, ptt, key,
                                        q2_sql_encode_value(q2, attrs, from),
                                        key,
                                        q2_sql_encode_value(q2, attrs, to));
            } else if (range_toks->nelts == 1) {
                from = APR_ARRAY_IDX(range_toks, 0, const char*);
                strcpy(ptt, value_v[0] == ',' ? "(%s<=%s)" : "(%s>=%s)");
                parsed_v = apr_psprintf(q2->pool, ptt, key,
                                        q2_sql_encode_value(q2, attrs, from));
            }
            return parsed_v;
        }
        else if (q2_in_string(filter, 's')) {
            set_toks = q2_split(q2->pool, (char*)value_v, ",");
            if (set_toks->nelts > 0) {
                apr_array_header_t *tmp =
                    apr_array_make(q2->pool, 1, sizeof(const char*));
                for (int i = 0; i < set_toks->nelts; i ++) {
                    const char *cur_v = APR_ARRAY_IDX(set_toks, i, const char*);
                    encoded_v = q2_sql_encode_value(q2, attrs, cur_v);
                    if (q2_is_null_s(encoded_v))
                        strcpy(ptt, "%s IS NULL");
                    else if (character_set_name != NULL)
                        strcpy(ptt, "(%s LIKE %s)");
                    else if (is_date)
                        strcpy(ptt, "(%s=%s)");
                    else
                        strcpy(ptt, "(%s=%s)");
                    APR_ARRAY_PUSH(tmp, const char*) =
                        apr_psprintf(q2->pool, ptt, key, encoded_v);
                }
                parsed_v = q2_join(q2->pool, tmp, " OR ");
            }
            return apr_pstrcat(q2->pool, "(", parsed_v, ")", NULL);
        }
    }
    value_len = strlen(value_v);
    if ((value_len == 1) && (value_v[0] == '*')) return NULL;
    encoded_v = q2_sql_encode_value(q2, attrs, value_v);
    if (q2_is_null_s(encoded_v)) strcpy(ptt, "%s IS NULL");
    else if (character_set_name != NULL) strcpy(ptt, "(%s LIKE %s)");
    else if (is_date) strcpy(ptt, "(%s=%s)");
    else strcpy(ptt, "(%s=%s)");
    return apr_psprintf(q2->pool, ptt, key, encoded_v);
}

static const char* q2_sql_key_conds(q2_t *q2)
{
    const char *pk_name, *pk_val, *pk_conds_s, *curr_uri_tab, *ref_table;
    apr_array_header_t *pk_conds;
    if (q2->uri_keys != NULL) {
        pk_conds = NULL;
        pk_conds_s = NULL;
        if (q2->uri_tables->nelts > 1) {
            for (int i = 0; i < q2->uri_tables->nelts-1; i ++) {
                curr_uri_tab = APR_ARRAY_IDX(q2->uri_tables, i, const char*);
                if (curr_uri_tab == NULL) continue;
                for (int j = 0; j < q2->attributes->nelts; j ++) {
                    ref_table = q2_dbd_get_value(q2->attributes,
                                                 j, "referenced_table");
                    if (ref_table == NULL) continue;
                    if (strcmp(curr_uri_tab, ref_table) != 0) continue;
                    const char *is_pk = q2_dbd_get_value(q2->attributes,
                                                         j, "is_primary_key");
                    if (is_pk == NULL || !(unsigned char)atoi(is_pk)) continue;
                    pk_name = q2_dbd_get_value(q2->attributes,
                                               j, "column_name");
                    if (pk_name == NULL) continue;
                    pk_val = APR_ARRAY_IDX(q2->uri_keys, i, const char*);
                    if (pk_val == NULL) continue;
                    if (pk_conds == NULL)
                        pk_conds = apr_array_make(q2->pool,
                                                  1, sizeof(const char*));
                    APR_ARRAY_PUSH(pk_conds, const char*) =
                        apr_psprintf(q2->pool,
                                     q2_is_integer(pk_val)
                                        ? "(%s=%s)"
                                        : "(%s='%s')",
                                     pk_name, pk_val);
                }
            }
        }
        else if (q2->uri_tables->nelts == 1) {
            for (int i = 0; i < q2->attributes->nelts; i ++) {
                const char *is_pk = q2_dbd_get_value(q2->attributes,
                                                     0, "is_primary_key");
                if (is_pk == NULL || !(unsigned char)atoi(is_pk)) continue;
                pk_name = q2_dbd_get_value(q2->attributes, 0, "column_name");
                if (pk_name == NULL) return NULL;
            }
            if(pk_name == NULL) return NULL;
            pk_val = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
            if (pk_val == NULL) return NULL;
            if (pk_conds == NULL)
                pk_conds = apr_array_make(q2->pool, 1, sizeof(const char*));

            APR_ARRAY_PUSH(pk_conds, const char*) =
                apr_psprintf(q2->pool,
                             q2_is_integer(pk_val) ? "(%s=%s)" : "(%s='%s')",
                             pk_name, pk_val);
        }
        if (pk_conds != NULL) {
            pk_conds_s = q2_join(q2->pool, pk_conds, " AND ");
            if (pk_conds_s == NULL) return NULL;
        }
        return pk_conds_s;
    }
    return NULL;
}

static int q2_count_rows(q2_t* q2, const char *sql)
{
    int er;
    const char *qry = "select count(*) as c from (%s) as t";
    const char *sql_c = apr_psprintf(q2->pool, qry, sql);
    apr_array_header_t *res = q2_dbd_select(q2->pool, q2->dbd_driver,
                                            q2->dbd_handle, sql_c, &er);
    if (res != NULL && res->nelts > 0) {
        apr_table_t *tab = APR_ARRAY_IDX(res, 0, apr_table_t*);
        if (tab != NULL) {
            const char *count_s = apr_table_get(tab, "c");
            if (count_s != NULL) {
                return atoi(count_s);
            }
        }
    }
    return 0;
}

static const char* q2_sql_select_tab(q2_t *q2)
{
    const char *sql, *limit;
    unsigned char ok = (unsigned char)(q2->uri_tables != NULL &&
                         q2->uri_tables->nelts == 1 &&
                         q2->uri_keys == NULL && q2->table != NULL &&
                         q2->column == NULL && q2->r_params == NULL);
    if(!ok) return NULL;

    limit = NULL;
    if (q2->dbd_server_type == Q2_DBD_MSSQL) {
        const char *pk_name = NULL;
        for (int i = 0; i < q2->attributes->nelts; i ++) {
            int is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes,
                                                             i,
                                                             "is_primary_key"));
            if (is_pk) pk_name = q2_dbd_get_value(q2->attributes,
                                                  i, "column_name");
        }
        if (pk_name == NULL) {
            q2_log_error(q2, "%s", "Primary key not found");
            return NULL;
        }
        limit = apr_psprintf(q2->pool,
                             "ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY",
                             pk_name, q2->next_page, q2->pagination_ppg);
    }
    if (q2->dbd_server_type == Q2_DBD_PGSQL ||
        q2->dbd_server_type == Q2_DBD_SQLT3)
    {
        limit = apr_psprintf(q2->pool,
                             "LIMIT %d OFFSET %d",
                             q2->pagination_ppg, q2->next_page);
    }
    if (q2->dbd_server_type == Q2_DBD_MYSQL && q2->pagination_ppg) {
        limit = apr_psprintf(q2->pool,
                             "LIMIT %d,%d",
                             q2->next_page, q2->pagination_ppg);
    }
    sql = apr_psprintf(q2->pool, "SELECT * FROM %s", q2->table);
    q2->query_num_rows = q2_count_rows(q2, sql);
    return apr_psprintf(q2->pool,
}

static const char* q2_sql_select_tab_key(q2_t *q2)
{
    unsigned char ok;
    const char *key_conds_s;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                         q2->uri_tables->nelts == 1 && q2->uri_keys != NULL &&
                         q2->table != NULL && q2->column == NULL &&
                         q2->r_params == NULL);
    if (!ok) return NULL;
    q2->single_entity = 1;
    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s%s", "*",
                        q2->table, key_conds_s, "");
}

static const char* q2_sql_select_tab_col(q2_t *q2)
{
    unsigned char ok, is_pk, uri_column_is_pk;
    const char *pk_conds_s, *pk_name, *pks_s;
    apr_array_header_t* pks_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->uri_keys == NULL &&
                  q2->table != NULL && q2->column != NULL &&
                  q2->r_params == NULL);
    if (!ok) return NULL;

    pks_ar = NULL;
    uri_column_is_pk = 0;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
        if (!is_pk) continue;
        pk_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (pk_name == NULL) return NULL;
        if (pks_ar == NULL)
            pks_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
        if (pks_ar == NULL) return NULL;
        APR_ARRAY_PUSH(pks_ar, const char*) = pk_name;
        if (strcmp(pk_name, q2->column) == 0) uri_column_is_pk = 1;
    }
    pks_s = NULL;
    if (pks_ar != NULL && pks_ar->nelts > 0)
        pks_s = apr_array_pstrcat(q2->pool, pks_ar, ',');
    return apr_psprintf(q2->pool, "SELECT %s%s%s FROM %s%s",
            pks_s == NULL ? "" : pks_s,
            pks_s == NULL || uri_column_is_pk ? "" : ",",
            uri_column_is_pk ? "" : q2->column,
            q2->table, "");
}

static const char* q2_sql_select_tab_col_prm(q2_t *q2)
{
    unsigned char ok, is_pk, uri_column_is_pk;
    const char *pk_conds_s, *c_name, *c_val, *pks_s, *pars_v, *conds_s, *ordby_s;
    apr_table_t *c_attr;
    apr_array_header_t *conds_ar, *ordby_ar, *pks_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->uri_keys == NULL &&
                  q2->table != NULL && q2->column != NULL &&
                  q2->r_params != NULL);
    if (!ok) return NULL;

    pks_ar = NULL;
    pars_v = NULL;
    ordby_ar = NULL;
    conds_ar = NULL;
    conds_s = NULL;
    uri_column_is_pk = 0;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val != NULL) {
            c_attr = q2_dbd_get_entry(q2->attributes, i);
            pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
            if (pars_v != NULL) {
                if (conds_ar == NULL) {
                    conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
                    if (conds_ar == NULL) return NULL;
                }
                APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
            }
        }
        is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
        if (!is_pk) continue;
        if (pks_ar == NULL)
            pks_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
        if (pks_ar == NULL) return NULL;    
        APR_ARRAY_PUSH(pks_ar, const char*) = c_name;
        if (strcmp(c_name, q2->column) == 0) uri_column_is_pk = 1;
    }
    pks_s = NULL;
    if (pks_ar != NULL && pks_ar->nelts > 0)
        pks_s = apr_array_pstrcat(q2->pool, pks_ar, ',');
    conds_s = NULL;
    if (conds_ar != NULL)
        conds_s = q2_join(q2->pool, conds_ar, " AND ");
    ordby_s = NULL;
    if (ordby_ar != NULL)
        ordby_s = apr_psprintf(q2->pool, " ORDER BY %s",
                               apr_array_pstrcat(q2->pool, ordby_ar, ','));
    return apr_psprintf(q2->pool, "SELECT %s%s%s FROM %s%s%s%s",
                        pks_s == NULL ? "" : pks_s,
                        pks_s == NULL || uri_column_is_pk ? "" : ",",
                        uri_column_is_pk ? "" : q2->column,
                        q2->table,
                        conds_s == NULL ? "" : " WHERE ",
                        conds_s == NULL ? "" : conds_s,
                        ordby_s == NULL ? "" : ordby_s);
}

static const char* q2_sql_select_tab_prm(q2_t *q2)
{
    unsigned char ok;
    const char *c_name, *c_val, *conds_s, *pars_v, *ordby_s, *sql, *limit;
    apr_table_t *c_attr;
    apr_array_header_t *conds_ar, *ordby_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->table != NULL &&
                  q2->column == NULL && q2->r_params != NULL &&
                  q2->uri_keys == NULL);
    if (!ok) return NULL;

    conds_ar = NULL;
    ordby_ar = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val == NULL) continue;
        c_attr = q2_dbd_get_entry(q2->attributes, i);
        pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
        if (pars_v != NULL) {
            if (conds_ar == NULL) {
                conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
                if (conds_ar == NULL) return NULL;
            }
            APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
        }
    }
    conds_s = NULL;
    if (conds_ar != NULL) {
        conds_s = q2_join(q2->pool, conds_ar, " AND ");
        if (conds_s == NULL) return NULL;
    }
    ordby_s = NULL;
    if (ordby_ar != NULL)
        ordby_s = apr_psprintf(q2->pool, " ORDER BY %s",
                               apr_array_pstrcat(q2->pool, ordby_ar, ','));
    if (conds_s == NULL) {
        sql = apr_psprintf(q2->pool, "SELECT %s FROM %s%s", "*",
                            q2->table, ordby_s == NULL ? "" : ordby_s);
    } else {
        sql = apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s%s", "*",
                           q2->table, conds_s,
                           ordby_s == NULL ? "" : ordby_s);
    }

    limit = NULL;
    if (q2->dbd_server_type == Q2_DBD_MSSQL) {
        const char *pk_name = NULL;
        for (int i = 0; i < q2->attributes->nelts; i ++) {
            int is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
            if (is_pk) pk_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        }
        if (pk_name == NULL) {
            q2_log_error(q2, "%s", "Primary key not found");
            return NULL;
        }
        limit = apr_psprintf(q2->pool,
                             "ORDER BY %s OFFSET %d ROWS FETCH NEXT %d ROWS ONLY",
                             pk_name, q2->next_page, q2->pagination_ppg);
    }
    if (q2->dbd_server_type == Q2_DBD_PGSQL ||
        q2->dbd_server_type == Q2_DBD_SQLT3)
    {
        limit = apr_psprintf(q2->pool,
                             "LIMIT %d OFFSET %d",
                             q2->pagination_ppg, q2->next_page);
    }
    if (q2->dbd_server_type == Q2_DBD_MYSQL && q2->pagination_ppg) {
        limit = apr_psprintf(q2->pool,
                             "LIMIT %d,%d",
                             q2->next_page, q2->pagination_ppg);
    }

    q2->query_num_rows = q2_count_rows(q2, sql);

    return apr_psprintf(q2->pool,
}

static const char* q2_sql_select_tab_key_prm(q2_t *q2)
{
    unsigned char ok;
    const char *c_name, *c_val, *conds_s, *key_conds_s, *pars_v, *ordby_s;
    apr_table_t *c_attr;
    apr_array_header_t *ordby_ar, *conds_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->table != NULL &&
                  q2->column == NULL && q2->r_params != NULL &&
                  q2->uri_keys != NULL);
        
    if (!ok) return NULL;
    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;
    if (q2->attributes == NULL || q2->attributes->nelts <= 0) return NULL;
    conds_ar = NULL;
    ordby_ar = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val == NULL) continue;
        c_attr = q2_dbd_get_entry(q2->attributes, i);
        pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
        if (pars_v != NULL) {
            if (conds_ar == NULL) {
                conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
                if (conds_ar == NULL) return NULL;
            }
            APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
        }
    }
    conds_s = NULL;
    if (conds_ar != NULL) {
        conds_s = q2_join(q2->pool, conds_ar, " AND ");
        if (conds_s == NULL) return NULL;
    }
    ordby_s = NULL;
    if (ordby_ar != NULL)
        ordby_s = apr_psprintf(q2->pool, " ORDER BY %s",
                               apr_array_pstrcat(q2->pool, ordby_ar, ','));
    if (conds_s == NULL)
        return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s%s", "*",
                            q2->table, key_conds_s,
                            ordby_s == NULL ? "" : ordby_s);
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s AND %s%s", "*",
                        q2->table, conds_s, key_conds_s,
                        ordby_s == NULL ? "" : ordby_s);
}

static const char* q2_sql_select_tab_key_col(q2_t *q2)
{
    unsigned char ok;
    const char *key_conds_s;
    
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params == NULL);
    
    if (!ok) return NULL;

    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;



    return apr_psprintf(q2->pool,
                        "SELECT %s FROM %s WHERE %s%s",
                        q2->column,
                        q2->table,
                        key_conds_s,
                        "");
}

static const char* q2_sql_select_tab_key_col_prm(q2_t *q2)
{
    unsigned char ok;
    const char *key_conds_s;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts == 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params != NULL);

    if (!ok) return NULL;

    q2_log_error(q2, "%s", "Function temporarily unavailable");

    return NULL;
}

static const char* q2_sql_select_tabs_key_mm(q2_t *q2)
{
    unsigned char ok;
    const char *key_conds_s;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts > 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params == NULL &&
                  q2->tab_relation == Q2_RL_MMREL);
    if (!ok) return NULL;
    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s%s", "*",
                        q2->table, key_conds_s, "");
}

static const char* q2_sql_select_tabs_key(q2_t *q2)
{
    const char *t_name, *c_name, *c_val, *first_uri_tab;
    first_uri_tab = APR_ARRAY_IDX(q2->uri_tables, 0, const char*);
    if (first_uri_tab == NULL) return NULL;
    if (q2->attributes->nelts <= 0) return NULL;
    c_name = NULL;
    c_val = NULL;
    for (int i = 0; i < q2->attributes->nelts;  i ++) {
        t_name = q2_dbd_get_value(q2->attributes, i, "referenced_table");
        if (t_name == NULL) continue;
        if (strcmp(t_name, first_uri_tab) != 0) continue;
        if (c_name != NULL) continue;
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) return NULL;
        c_val = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
        if (c_val == NULL) return NULL;
    }
    return apr_psprintf(q2->pool,
                        q2_is_integer(c_val)
                            ? "SELECT %s FROM %s WHERE %s=%s%s"
                            : "SELECT %s FROM %s WHERE %s='%s'%s",
                        "*", q2->table, c_name, c_val, "");
}
static const char* q2_sql_select_tabs_key_11(q2_t *q2)
{
    unsigned char ok = (unsigned char)(q2->uri_tables != NULL &&
                         q2->uri_tables->nelts > 1 &&
                         q2->table != NULL && q2->uri_keys != NULL &&
                         q2->r_params == NULL &&
                         q2->tab_relation == Q2_RL_11REL);
    if (!ok) return NULL;
    return q2_sql_select_tabs_key(q2);
}

static const char* q2_sql_select_tabs_key_1m(q2_t *q2)
{
    unsigned char ok = (unsigned char)(q2->uri_tables != NULL &&
                         q2->uri_tables->nelts > 1 &&
                         q2->table != NULL && q2->uri_keys != NULL &&
                         q2->r_params == NULL &&
                         q2->tab_relation == Q2_RL_1MREL);
    if (!ok) return NULL;
    return q2_sql_select_tabs_key(q2);
}

static const char* q2_sql_select_tabs_key_prm_11(q2_t *q2)
{
    unsigned char ok;
    const char *key_conds_s, *conds_s, *c_name, *c_val, *pars_v, *first_uri_tab;
    apr_table_t *c_attr;
    apr_array_header_t *conds_ar, *ordby_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts > 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params != NULL &&
                  q2->tab_relation == Q2_RL_11REL);
    if (!ok) return NULL;
    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;
    first_uri_tab = APR_ARRAY_IDX(q2->uri_tables, 0, const char*);
    if (q2->attributes->nelts <= 0) return NULL;
    conds_ar = NULL;
    ordby_ar = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val == NULL) continue;
        c_attr = q2_dbd_get_entry(q2->attributes, i);
        pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
        if (pars_v != NULL) {
            if (conds_ar == NULL) {
                conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
                if (conds_ar == NULL) return NULL;
            }
            APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
        }
    }
    conds_s = NULL;
    if (conds_ar != NULL)    
        conds_s = q2_join(q2->pool, conds_ar, " AND ");
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s AND %s%s", "*",
                        q2->table, conds_s, key_conds_s, "");
}

static const char* q2_sql_select_tabs_key_prm_1m(q2_t *q2)
{
    unsigned char ok;
    const char *t_name, *k_name, *c_name, *k_val, *c_val, *pars_v, *conds_s,
           *ordby_s, *first_uri_tab;
    apr_table_t *c_attr;
    apr_array_header_t *conds_ar, *ordby_ar;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts > 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params != NULL &&
                  q2->tab_relation == Q2_RL_1MREL);
    if (!ok) return NULL;
    first_uri_tab = APR_ARRAY_IDX(q2->uri_tables, 0, const char*);
    if (q2->attributes->nelts <= 0) return NULL;
    k_name = NULL;
    k_val = NULL;
    conds_ar = NULL;
    ordby_ar = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        t_name = q2_dbd_get_value(q2->attributes, i, "referenced_table");
        if (t_name == NULL) continue;
        if (strcmp(t_name, first_uri_tab) == 0) {
            k_name = q2_dbd_get_value(q2->attributes, i, "column_name");
            k_val = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
            if (k_name == NULL || k_val == NULL) return NULL;
            continue;
        }
        c_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val == NULL) continue;
        c_attr = q2_dbd_get_entry(q2->attributes, i);
        pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
        if (pars_v == NULL) continue;
        if (conds_ar == NULL) {
            conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
            if (conds_ar == NULL) return NULL;
        }
        APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
    }
    if (k_name == NULL || k_val == NULL || conds_ar == NULL) return NULL;
    conds_s = q2_join(q2->pool, conds_ar, " AND ");
    if (conds_s == NULL) return NULL;
    ordby_s = NULL;
    if (ordby_ar != NULL)
        ordby_s = apr_psprintf(q2->pool, " ORDER BY %s",
                               apr_array_pstrcat(q2->pool, ordby_ar, ','));
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s AND (%s=%s)%s",
                        "*", q2->table, conds_s, k_name, k_val,
                        ordby_s != NULL ? ordby_s : "");
}

static const char* q2_sql_select_tabs_key_prm_mm(q2_t *q2)
{
    int err;
    unsigned char ok;
    const char *lst_uri_tab, *sub_query, *conds_s, *key_conds_s, *c_name, *c_val,
           *pars_v, *ordby_s, *select_what, *lst_uri_tab_pk;
    apr_table_t *c_attr;
    apr_array_header_t *conds_ar, *ordby_ar, *lst_uri_tab_col_attrs, *lst_uri_tab_pk_attrs;
    ok = (unsigned char)(q2->uri_tables != NULL &&
                  q2->uri_tables->nelts > 1 && q2->table != NULL &&
                  q2->uri_keys != NULL && q2->r_params != NULL &&
                  q2->tab_relation == Q2_RL_MMREL);
    if (!ok) return NULL;
    key_conds_s = q2_sql_key_conds(q2);
    if (key_conds_s == NULL) return NULL;
    lst_uri_tab = APR_ARRAY_IDX(q2->uri_tables,
                                q2->uri_tables->nelts-1, const char*);
    apr_array_header_t *tmp_targets = apr_array_make(q2->pool,
                                                     1, sizeof(const char*));
    APR_ARRAY_PUSH(tmp_targets, const char*) = lst_uri_tab;
    lst_uri_tab_col_attrs = q2_ischema_get_col_attrs(q2, lst_uri_tab);
    if (lst_uri_tab_col_attrs == NULL) return NULL;
    lst_uri_tab_pk_attrs = q2_ischema_get_pk_attrs(q2, lst_uri_tab);
    if (lst_uri_tab_pk_attrs == NULL) return NULL;
    if (lst_uri_tab_col_attrs->nelts <= 0) return NULL;
    conds_ar = NULL;
    ordby_ar = NULL;
    for (int i = 0; i < lst_uri_tab_col_attrs->nelts; i ++) {
        c_name = q2_dbd_get_value(lst_uri_tab_col_attrs, i, "column_name");
        if (c_name == NULL) continue;
        c_val = apr_table_get(q2->r_params, c_name);
        if (c_val == NULL) continue;
        c_attr = q2_dbd_get_entry(lst_uri_tab_col_attrs, i);
        pars_v = q2_sql_parse_value(q2, c_attr, c_name, c_val, &ordby_ar);
        if (pars_v != NULL) {
            if (conds_ar == NULL) {
                conds_ar = apr_array_make(q2->pool, 1, sizeof(const char*));
                if (conds_ar == NULL) return NULL;
            }
            APR_ARRAY_PUSH(conds_ar, const char*) = pars_v;
        }
    }
    conds_s = NULL;
    if (conds_ar != NULL && conds_ar->nelts > 0)
        conds_s = apr_pstrcat(q2->pool, " AND ",
                              q2_array_pstrcat(q2->pool, conds_ar, " AND "),
                              NULL);
    ordby_s = NULL;
    if (ordby_ar != NULL && ordby_ar->nelts > 0)
        ordby_s = apr_psprintf(q2->pool, " ORDER BY %s",
                                apr_array_pstrcat(q2->pool, ordby_ar, ','));
    select_what = q2_dbd_get_value(q2->pk_attrs, 
                                   q2->pk_attrs->nelts -1, "column_name");
    lst_uri_tab_pk = q2_dbd_get_value(lst_uri_tab_pk_attrs, 0, "column_name");
    sub_query = apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s%s",
                             select_what, q2->table, key_conds_s, "");
    return apr_psprintf(q2->pool, "SELECT %s FROM %s WHERE %s IN (%s)%s%s", "*",
                        lst_uri_tab, lst_uri_tab_pk, sub_query,
                        conds_s == NULL ? "" : conds_s,
                        ordby_s == NULL ? "" : ordby_s);
}

static const char* q2_sql_select(q2_t *q2)
{
    const char *sql;
    if ((sql = q2_sql_select_tab(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_key(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_prm(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_key_prm(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_col(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_col_prm(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_key_col(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tab_key_col_prm(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_11(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_1m(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_mm(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_prm_11(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_prm_1m(q2)) != NULL) return sql;
    if ((sql = q2_sql_select_tabs_key_prm_mm(q2)) != NULL) return sql;
    return NULL;
}

static const char* q2_sql_insert(q2_t *q2)
{
    unsigned char is_pk = 0, is_nullable = 0, is_auto_increment = 0, is_pk_multi = 0;
    const char *values_s = NULL, *keys_s = NULL, *k = NULL, *v = NULL;
    const char *referenced_table = NULL, *current_target = NULL;
    apr_array_header_t *keys = NULL, *params = NULL, *defaults = NULL;
    is_pk_multi = q2->pk_attrs->nelts > 1;
    if (!is_pk_multi) {
        for (int i = 0; i < q2->attributes->nelts; i ++) {
            is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
            if (!is_pk) continue;
            is_auto_increment = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_auto_increment"));
            if (!is_auto_increment) {
                if (q2->uri_keys != NULL && q2->uri_keys->nelts > 0) {
                    k = q2_dbd_get_value(q2->attributes, i, "column_name");
                    v = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
                    if (q2->r_params == NULL)
                        q2->r_params = apr_table_make(q2->pool, 0);
                    apr_table_setn(q2->r_params, k, v);
                }
            }
            break;
        }
    }
    if (q2->uri_tables->nelts > 1) {
        for (int i = 0; i < q2->attributes->nelts; i ++) {
            is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
            if (!is_pk) continue;
            referenced_table = q2_dbd_get_value(q2->attributes, i, "referenced_table");
            for (int j = 0; j < q2->uri_tables->nelts; j ++) {
                current_target = APR_ARRAY_IDX(q2->uri_tables, j, const char*);
                if (strcmp(referenced_table, current_target) == 0) {
                    k = q2_dbd_get_value(q2->attributes, i, "column_name");
                    v = APR_ARRAY_IDX(q2->uri_keys, j, const char*);
                    if (q2->r_params == NULL)
                        q2->r_params = apr_table_make(q2->pool, 0);
                    apr_table_setn(q2->r_params, k, v);
                }
            }
        }
    }
    keys = apr_array_make(q2->pool, q2->attributes->nelts, sizeof(const char*));
    if (keys == NULL) return NULL;
    defaults = apr_array_make(q2->pool, q2->attributes->nelts, sizeof(const char*));
    if (defaults == NULL) return NULL;
    params = apr_array_make(q2->pool, q2->attributes->nelts, sizeof(const char*));
    if (params == NULL) return NULL;
    k = NULL;
    v = NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        k = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (k == NULL) return NULL;
        APR_ARRAY_PUSH(keys, const char*) = k;
        is_nullable = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_nullable"));
        is_pk = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
        is_auto_increment = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_auto_increment"));
        if (!is_auto_increment && !is_nullable) {
            if (q2->r_params != NULL) v = apr_table_get(q2->r_params, k);
            if (v == NULL) {
                const char *err = apr_psprintf(q2->pool, "Parameter %s is mandatory", k);
                return NULL;
            }
            APR_ARRAY_PUSH(defaults, const char*) = apr_pstrdup(q2->pool, v);
        } else {
            APR_ARRAY_PUSH(defaults, const char*) = apr_pstrdup(q2->pool, "default");
        }
    }
    keys_s = apr_array_pstrcat(q2->pool, keys, ',');
    if (keys_s == NULL) return NULL;
    if (params->nelts == q2->attributes->nelts) {
        values_s = apr_array_pstrcat(q2->pool, params, ',');
        if (values_s == NULL) return NULL;
    } else {
        values_s = apr_array_pstrcat(q2->pool, defaults, ',');
        if (values_s == NULL) return NULL;
    }
    return apr_psprintf(q2->pool, "INSERT INTO %s (%s) VALUES (%s)",
                        q2->table, keys_s, values_s);
}

static const char* q2_sql_update(q2_t *q2, int all)
{
    unsigned char is_numeric = 0, is_primary_key = 0, params_ok;
    int pairs_num = 0;
    const char *pairs_s = NULL, *pk_name = NULL, *pk_value = NULL;
    const char *col_name = NULL, *col_value = NULL;
    apr_array_header_t *pairs_arr = NULL;
    if (q2->uri_keys == NULL) {
        q2_log_error(q2, "%s", "No primary key in URI");
        return NULL;
    }
    if (all && q2->r_params == NULL) {
        q2_log_error(q2, "%s", "No parameters in REQUEST");
        return NULL;
    }
    if (!all && q2->request_rawdata == NULL) {
        q2_log_error(q2, "%s", "No data in REQUEST");
        return NULL;
    }
    if (all && q2->r_params != NULL) {
        params_ok = (unsigned char)(apr_table_elts(q2->r_params)->nelts == (q2->attributes->nelts-1));
        if (!params_ok) {
            q2_log_error(q2, "%s", "Too few REQUEST parameters");
            return NULL;
        }
    }
    if (q2->pk_attrs->nelts > 1) {
        q2_log_error(q2,
                     "%s", "UPDATE not allowed on a table with multiple PK");
        return NULL;
    }
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        is_primary_key = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_primary_key"));
        if (is_primary_key) continue;
        is_numeric = (unsigned char)atoi(q2_dbd_get_value(q2->attributes, i, "is_numeric"));
        col_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (col_name == NULL) continue;
        col_value = NULL;
        if (q2->r_params != NULL)
            col_value = apr_table_get(q2->r_params, col_name);
        if (col_value == NULL) {
            if (all) {
                q2_log_error(q2, "'%s' is mandatory", col_name);
                return NULL;
            } else {
                if (q2->column == NULL) continue;
                if (strcmp(q2->column, col_name) != 0) continue;
                col_value = q2->request_rawdata;
                if (col_value == NULL) {
                    q2_log_error(q2, "'%s' has no valid value", col_name);
                    return NULL;
                }
            }
        }
        if (pairs_arr == NULL) {
            pairs_arr = apr_array_make(q2->pool, 1, sizeof(const char*));
            if (pairs_arr == NULL) return NULL;
        }
        APR_ARRAY_PUSH(pairs_arr, const char*) =
            apr_psprintf(q2->pool, "%s=%s", col_name,
                         is_numeric
                            ? col_value
                            : q2_sql_encode_value(
                                q2, q2_dbd_get_entry(q2->attributes, i),
                                col_value));

        pairs_num ++;
    }
    if (pairs_arr == NULL) {
        q2_log_error(q2, "%s", "No request parameters found");
        return NULL;
    }
    if (all && pairs_num < (q2->attributes->nelts-1)) {
        q2_log_error(q2, "%s", "Too few request parameters");
        return NULL;
    }
    pairs_s = apr_array_pstrcat(q2->pool, pairs_arr, ',');
    if (pairs_s == NULL) return NULL;
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        const char *is_pk =
            q2_dbd_get_value(q2->attributes, i, "is_primary_key");
        if (is_pk == NULL || !(unsigned char)atoi(is_pk)) continue;
        pk_name = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (pk_name == NULL) return NULL;
    }
    if (pk_name == NULL) {
        q2_log_error(q2, "%s", "Table without primary key");
        return NULL;
    }
    pk_value = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
    if (pk_value == NULL) {
        q2_log_error(q2, "%s", "No primary key in URI");
        return NULL;
    }
    return apr_psprintf(q2->pool, "UPDATE %s SET %s WHERE %s=%s",
                        q2->table, pairs_s, pk_name, pk_value);
}

static const char* q2_sql_delete(q2_t *q2)
{
    const char *cname = NULL, *cval = NULL, *ref_table = NULL, *target = NULL;
    const char *key_conds_s = NULL;
    apr_array_header_t *key_conds = NULL;
    if (q2->uri_keys == NULL) {
        q2_log_error(q2, "%s", "No primary key in URI");
        return NULL;
    }
    for (int i = 0; i < q2->attributes->nelts; i ++) {
        cname = q2_dbd_get_value(q2->attributes, i, "column_name");
        if (cname == NULL) return NULL;
        ref_table = q2_dbd_get_value(q2->attributes, i, "referenced_table");
        if (ref_table != NULL) {
            for (int j = 0; j < q2->uri_keys->nelts; j ++) {
                target = APR_ARRAY_IDX(q2->uri_tables, j, const char*);
                if (target == NULL) continue;
                if (strcmp(target, ref_table) == 0) {
                    if (cval == NULL) {
                        cval = APR_ARRAY_IDX(q2->uri_keys, j, const char*);
                        if (key_conds == NULL) {
                            key_conds = apr_array_make(q2->pool,
                                                       1, sizeof(const char*));
                            if (key_conds == NULL) return NULL;
                        }
                        APR_ARRAY_PUSH(key_conds, const char*) =
                            apr_psprintf(q2->pool, "(%s=%s)", cname, cval);
                    }
                }
            }
        }
    }
    if (key_conds == NULL) {
        if (q2->pk_attrs->nelts > 1) {
            q2_log_error(q2,
                         "%s", "Table with multiple primary key");
            return NULL;
        }
        cname = q2_dbd_get_value(q2->pk_attrs, 0, "column_name");
        if (cname == NULL) {
            q2_log_error(q2,
                         "%s", "Table without primary key");
            return NULL;
        }
        cval = APR_ARRAY_IDX(q2->uri_keys, 0, const char*);
        if (cval == NULL) {
            q2_log_error(q2,
                         "%s", "No primary key in URI");
            return NULL;
        }
        return apr_psprintf(q2->pool, "DELETE FROM %s WHERE %s=%s",
                            q2->table, cname, cval);
    }
    if ((key_conds_s = q2_join(q2->pool, key_conds, " AND ")) == NULL)
        return NULL;
    return apr_psprintf(q2->pool, "DELETE FROM %s WHERE %s",
                        q2->table, key_conds_s);
}

static int q2_paginate_results(q2_t *q2)
{
    int next;
    const apr_strmatch_pattern *pattern;
    const char *next_p;
    const char *path, *new_path, *qstr;
    if (!q2->pagination_ppg) return 1;
    if (q2->sql == NULL || q2->results == NULL ||
        q2->results->nelts < q2->pagination_ppg) return 1;
    next = q2->pagination_ppg + q2->next_page;
    if (next > q2->query_num_rows) return 1;
    new_path = NULL;
    qstr = NULL;
    unsigned char found = q2_in_string(q2->request_uri, '?');
    if (found) {
        apr_array_header_t *ar = q2_split(q2->pool, q2->request_uri, "?");
        path = APR_ARRAY_IDX(ar, 0, const char*);
        qstr = APR_ARRAY_IDX(ar, 1, const char*);
    } else {
        path = apr_pstrdup(q2->pool, q2->request_uri);
    }
    pattern = apr_strmatch_precompile(q2->pool, "/next/", 1);
    next_p = apr_strmatch(pattern, path, strlen(path));
    if (next_p != NULL)
        new_path = apr_pstrndup(q2->pool, path,
                                (int)strlen(path) - (int)strlen(next_p));
    q2->next = apr_psprintf(q2->pool, "%s/next/%d%s%s",
                            new_path == NULL ? path : new_path,
                            next,
                            qstr == NULL ? "" : "?",
                            qstr == NULL ? "" : qstr);
    return 0;
}


static q2_t* q2_initialize(apr_pool_t *mp)
{
    q2_t *q2 = (q2_t*)apr_palloc(mp, sizeof(q2_t));
    if (q2 == NULL) return NULL;
    q2->pool = mp;
    q2->error = 0;
    q2->log = NULL;
    q2->dbd_driver = NULL;
    q2->dbd_handle = NULL;
    q2->dbd_server_type = 0;
    q2->attributes = NULL;
    q2->sql = NULL;
    q2->results = NULL;
    q2->affected_rows = 0;
    q2->last_insert_id = NULL;
    q2->tb_name_fn = NULL;
    q2->cl_name_fn = NULL;
    q2->cl_attr_fn = NULL;
    q2->pk_attr_fn = NULL;
    q2->fk_tabs_fn = NULL;
    q2->fk_attr_fn = NULL;
    q2->un_attr_fn = NULL;
    q2->id_last_fn = NULL;
    q2->db_vers_fn = NULL;
    q2->dbd_server_version = NULL;
    q2->next_page = 0;
    q2->next = NULL;
    q2->uri_tables = NULL;
    q2->uri_keys = NULL;
    q2->table = NULL;
    q2->request_uri = NULL;
    q2->tab_relation=0;
    q2->column = NULL;
    q2->pk_attrs = NULL;
    q2->unsigned_attrs = NULL;
    q2->refs_attrs = NULL;
    q2->request_params = NULL;
    q2->request_query = NULL;
    q2->request_rawdata = NULL;
    q2->request_rawdata_len = 0;
    q2->r_params = NULL;
    q2->r_others = NULL;
    q2->request_method = 0;
    q2->request_method_name = NULL;
    q2->query_num_rows = 0;
    q2->pagination_ppg = 0;
    q2->single_entity = 0;
#ifdef _APMOD
    q2->r_rec = NULL;
#endif
    return q2;
}

static int q2_initialized(q2_t *q2)
{
    return (unsigned char)(q2->error == 0 &&
                           q2->log == NULL &&
                           q2->attributes == NULL &&
                           q2->sql == NULL &&
                           q2->results == NULL &&
                           q2->affected_rows == 0 &&
                           q2->last_insert_id == NULL);
}

#ifdef _APMOD
static void q2_set_request_rec(q2_t *q2, request_rec *r)
{
    q2->r_rec = r;
}
#endif

static void q2_set_dbd(q2_t *q2, const apr_dbd_driver_t *drv, apr_dbd_t *hd)
{
    q2->dbd_driver = drv;
    q2->dbd_handle = hd;
    const char *dbd_driver_name = apr_dbd_name(q2->dbd_driver);
    if (strncasecmp(dbd_driver_name, "mysql", 5) == 0)
        q2->dbd_server_type = Q2_DBD_MYSQL;
    if (strncasecmp(dbd_driver_name, "pgsql", 5) == 0)
        q2->dbd_server_type = Q2_DBD_PGSQL;
    if (strncasecmp(dbd_driver_name, "sqlite3", 7) == 0)
        q2->dbd_server_type = Q2_DBD_SQLT3;
    if (strncasecmp(dbd_driver_name, "ODBC_DRIVER_NAME", 16) == 0)
        q2->dbd_server_type = Q2_DBD_MSSQL;
}

static void q2_set_method(q2_t *q2, const char* method)
{
    q2->request_method_name = method;
    if (strcmp(method, "GET") == 0)
        q2->request_method = Q2_HT_METHOD_GET;
    if (strcmp(method, "POST") == 0)
        q2->request_method = Q2_HT_METHOD_POST;
    if (strcmp(method, "PUT") == 0)
        q2->request_method = Q2_HT_METHOD_PUT;
    if (strcmp(method, "PATCH") == 0)
        q2->request_method = Q2_HT_METHOD_PATCH;
    if (strcmp(method, "DELETE") == 0)
        q2->request_method = Q2_HT_METHOD_DELETE;
}

static void q2_set_uri(q2_t *q2, const char *uri)
{
    q2->request_uri = uri;
}

static void q2_set_query(q2_t *q2, const char *query)
{
    q2->request_query = query;
}

static void q2_set_params(q2_t *q2, apr_table_t *params)
{
    q2->request_params = params;
}

static void q2_set_ppg(q2_t *q2, int ppg)
{
    q2->pagination_ppg = ppg;
}

static void q2_set_rawdata(q2_t *q2, const char *data, int len)
{
    q2->request_rawdata = data;
    q2->request_rawdata_len = len;
}

static int q2_acquire(q2_t *q2)
{
    int er;
    int tab_found;
    const char *dbd_driver_name, *entity;
    apr_uri_t *ht_uri;
    apr_array_header_t *uri_arr;
    if (!q2_initialized(q2)) {
        q2_log_error(q2, "%s", "Q2 not initialized");
        return 1;
    }
    if (q2->dbd_driver == NULL ||
        q2->dbd_handle == NULL ||
        q2->dbd_server_type == 0) {
        q2_log_error(q2, "%s", "DBD error");
        return 1;
    }
    #if !defined (Q2DBD) || defined (MYSQL)
    if (q2->dbd_server_type == Q2_DBD_MYSQL) {
        q2->tb_name_fn = q2_mysql_tb_name;
        q2->cl_name_fn = q2_mysql_cl_name;
        q2->cl_attr_fn = q2_mysql_cl_attr;
        q2->pk_attr_fn = q2_mysql_pk_attr;
        q2->un_attr_fn = q2_mysql_un_attr;
        q2->fk_tabs_fn = q2_mysql_fk_tabs;
        q2->fk_attr_fn = q2_mysql_fk_attr;
        q2->id_last_fn = q2_mysql_id_last;
        q2->db_vers_fn = q2_mysql_getvers;
    }
    #endif
    #if !defined (Q2DBD) || defined (PGSQL)
    if (q2->dbd_server_type == Q2_DBD_PGSQL) {
        q2->tb_name_fn = q2_pgsql_tb_name;
        q2->cl_name_fn = q2_pgsql_cl_name;
        q2->cl_attr_fn = q2_pgsql_cl_attr;
        q2->pk_attr_fn = q2_pgsql_pk_attr;
        q2->un_attr_fn = q2_pgsql_un_attr;
        q2->fk_tabs_fn = q2_pgsql_fk_tabs;
        q2->fk_attr_fn = q2_pgsql_fk_attr;
        q2->id_last_fn = q2_pgsql_id_last;
        q2->db_vers_fn = q2_pgsql_getvers;
    }
    #endif
    #if !defined (Q2DBD) || defined (SQLITE3)
    if (q2->dbd_server_type == Q2_DBD_SQLT3) {
        q2->tb_name_fn = q2_sqlt3_tb_name;
        q2->cl_name_fn = q2_sqlt3_cl_name;
        q2->cl_attr_fn = q2_sqlt3_cl_attr;
        q2->pk_attr_fn = q2_sqlt3_pk_attr;
        q2->un_attr_fn = q2_sqlt3_un_attr;
        q2->fk_tabs_fn = q2_sqlt3_fk_tabs;
        q2->fk_attr_fn = q2_sqlt3_fk_attr;
        q2->id_last_fn = q2_sqlt3_id_last;
        q2->db_vers_fn = q2_sqlt3_getvers;
    }
    #endif
    #if !defined (Q2DBD) || defined (MSSQL)
    if (q2->dbd_server_type == Q2_DBD_MSSQL) {
        q2->tb_name_fn = q2_mssql_tb_name;
        q2->cl_name_fn = q2_mssql_cl_name;
        q2->cl_attr_fn = q2_mssql_cl_attr;
        q2->pk_attr_fn = q2_mssql_pk_attr;
        q2->un_attr_fn = q2_mssql_un_attr;
        q2->fk_tabs_fn = q2_mssql_fk_tabs;
        q2->fk_attr_fn = q2_mssql_fk_attr;
        q2->id_last_fn = q2_mssql_id_last;
        q2->db_vers_fn = q2_mssql_getvers;
    }
    #endif
    if (!q2->dbd_server_type) {
        q2_log_error(q2, "%s", "DBD driver not supported");
        return 1;
    }
    q2->dbd_server_version = q2->db_vers_fn(q2->pool, q2->dbd_driver,
                                            q2->dbd_handle, &er);
    if (q2->dbd_server_version == NULL) {
        if (er) {
            q2_log_error(q2, "%s", apr_dbd_error(q2->dbd_driver, q2->dbd_handle, er));
        } else {
            q2_log_error(q2, "%s", "Versione db non trovata");
        }
    }
    ht_uri = (apr_uri_t*)apr_palloc(q2->pool, sizeof(apr_uri_t));
    if (apr_uri_parse(q2->pool, q2->request_uri, ht_uri) != APR_SUCCESS) {
        q2_log_error(q2, "%s", "Invalid URI");
        return 1;
    }
    uri_arr = q2_split(q2->pool, ht_uri->path , "/");
    q2->next_page = q2_uri_get_pages(q2->pool, uri_arr);
    q2->uri_tables = q2_uri_get_tabs(q2->pool, uri_arr);
    q2->uri_keys = q2_uri_get_keys(q2->pool, uri_arr);
    tab_found = 0;
    q2->table = q2_ischema_get_target_table(q2, Q2_RL_11REL);
    tab_found = (int)(q2->table != NULL);
    if (tab_found) q2->tab_relation = Q2_RL_11REL;
    if (!tab_found) {
        q2->table = q2_ischema_get_target_table(q2, Q2_RL_1MREL);
        tab_found = (int)(q2->table != NULL);
        if (tab_found) q2->tab_relation = Q2_RL_1MREL;
    }
    if (!tab_found) {
        q2->table = q2_ischema_get_target_table(q2, Q2_RL_MMREL);
        tab_found = (int)(q2->table != NULL);
        if (tab_found) q2->tab_relation = Q2_RL_MMREL;
    }
    if (!tab_found) {
        q2->table = q2_ischema_get_target_table(q2, 0);
        tab_found = (int)(q2->table != NULL);
        if (tab_found && q2->uri_tables->nelts > 1) {
            q2->column = apr_pstrdup(q2->pool,
                                         APR_ARRAY_IDX(q2->uri_tables,
                                                       1, const char*));
            apr_array_pop(q2->uri_tables);
        }
    }
    if (!tab_found) {
        q2_log_error(q2, "%s", "Target table not found");
        return 1;
    }
    q2->attributes = q2_ischema_get_col_attrs(q2, q2->table);
    if (q2->attributes == NULL) {
        q2_log_error(q2, "%s", "q2_ischema_get_col_attrs() error");
        return 1;
    }
    q2->pk_attrs = q2_ischema_get_pk_attrs(q2, q2->table);
    if (q2->error) {
        q2_log_error(q2, "%s", "q2_ischema_get_pk_attrs() error");
        return 1;
    }
    q2->unsigned_attrs = q2_ischema_get_unsig_attrs(q2, q2->table);
    if (q2->error) {
        q2_log_error(q2, "%s", "q2_ischema_get_unsig_attrs() error");
        return 1;
    }
    q2->refs_attrs = q2_ischema_get_refs_attrs(q2, q2->table);
    if (q2->error) {
        q2_log_error(q2, "%s", "An error occurred");
        return 1;
    }
    q2_ischema_update_attrs(q2);




    if (q2->request_params == NULL && q2->request_query != NULL)
        q2_args_to_table(q2->pool, &(q2->request_params), q2->request_query);
    if (q2->request_params == NULL &&
        q2->request_rawdata != NULL && q2->column == NULL) {
        q2_args_to_table(q2->pool, &(q2->request_params), q2->request_rawdata);
    }
    q2->r_params = q2->request_params == NULL
        ? NULL 
        : q2_request_parse_params(q2);
    
    int n_params = 0, n_ht_params = 0;
    if (q2->r_params != NULL && q2->request_params != NULL) {
        n_params = apr_table_elts(q2->r_params)->nelts;
        n_ht_params = apr_table_elts(q2->request_params)->nelts;
        if (n_params < n_ht_params) {
            q2->r_others = apr_table_make(q2->pool, n_ht_params-n_params);
            for (int i = 0; i < n_ht_params; i ++) {
                apr_table_entry_t *e =
                    &((apr_table_entry_t*)((
                        apr_table_elts(q2->request_params))->elts))[i];
                    if (apr_table_get(q2->r_params, e->key) != NULL)
                        continue;
                    apr_table_set(q2->r_others,
                                  apr_pstrdup(q2->pool, e->key),
                                  apr_pstrdup(q2->pool, e->val));
            }
        }
    }

    q2_ischema_update_options_attr(q2);
    switch (q2->request_method)
    {
    case Q2_HT_METHOD_GET:
        q2->sql = q2_sql_select(q2);
        break;
    case Q2_HT_METHOD_POST:
        q2->sql = q2_sql_insert(q2);
        break;
    case Q2_HT_METHOD_PUT:
        q2->sql = q2_sql_update(q2, 1);
        break;
    case Q2_HT_METHOD_PATCH:
        q2->sql = q2_sql_update(q2, 0);
        break;
    case Q2_HT_METHOD_DELETE:
        q2->sql = q2_sql_delete(q2);
        break;
    default:
        q2_log_error(q2, "%s", "Invalid HTTP method");
        return 1;
    }
    if (q2->sql == NULL) {
        q2_log_error(q2, "%s", "SQL error");
        return 1;
    }
    if (q2->request_method == Q2_HT_METHOD_GET) {
        q2->results = q2_dbd_select(q2->pool, q2->dbd_driver,
                                    q2->dbd_handle, q2->sql, &q2->error);
        q2_paginate_results(q2);
    } else {
        q2->affected_rows = q2_dbd_query(q2->pool, q2->dbd_driver,
                                         q2->dbd_handle, q2->sql, &q2->error);
        if (!q2->error) {
            if (q2->request_method == Q2_HT_METHOD_POST) {
                q2->last_insert_id = q2_ischema_get_last_id(q2);
            }
        }
    }
    if (q2->error) {
        q2_log_error(q2, "%s",
                     apr_dbd_error(q2->dbd_driver, q2->dbd_handle, q2->error));
        return 1;
    }
    return 0;
}

static const char* q2_encode_json(q2_t *q2)
{
    size_t timestamp_len, out_len;
    char *out_s;
    const char *now, *dbd_driver_name;
    apr_status_t rv;
    dbd_driver_name = apr_dbd_name(q2->dbd_driver);
    out_s = apr_psprintf(
        q2->pool,
        Q2_OUTPUT_S,
        q2->error,
        q2->log == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->log),
        q2->request_method_name == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->request_method_name),
        dbd_driver_name == NULL
            ? "null"
            : q2_json_value(q2->pool, dbd_driver_name),
        q2->dbd_server_version == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->dbd_server_version),
        q2->table == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->table),
        q2->column == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->column),
        q2->sql == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->sql),
        q2->attributes == NULL || q2->request_method != Q2_HT_METHOD_GET
            ? "null"
            : q2_json_array(q2->pool, q2->attributes, Q2_TABLE),
        q2->results == NULL
            ? (q2->request_method == Q2_HT_METHOD_POST &&
               q2->last_insert_id != NULL
                    ? q2_json_value(q2->pool, 
                                    apr_psprintf(q2->pool,
                                                 "/%s/%s",
                                                 q2->table,
                                                 q2->last_insert_id))
                    : "null")
            : q2_json_array(q2->pool, q2->results, Q2_TABLE),
        q2->next == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->next),
        q2->affected_rows,
        q2->last_insert_id == NULL
            ? "null"
            : q2_json_value(q2->pool, q2->last_insert_id));
    return out_s;
}

static apr_array_header_t* q2_get_results(q2_t *q2)
{
    return q2->results;
}

static int q2_get_result(q2_t *q2, int i, const char **k, const char **v)
{
    if (q2->results != NULL) {
        if (q2->results->nelts >= (i+1)) {
            apr_table_t *t = APR_ARRAY_IDX(q2->results, i, apr_table_t*);
            if (t != NULL) {
                if ((apr_table_elts(t))->nelts > 0) {
                    apr_table_entry_t *e =
                        &((apr_table_entry_t*)((apr_table_elts(t))->elts))[0];
                    if (k != NULL) *k = apr_pstrdup(q2->pool, e->key);
                    *v = apr_pstrdup(q2->pool, e->val);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static int q2_contains_single_entity(q2_t *q2)
{
    return q2->single_entity == 1;
}

static const char* q2_get_last_id(q2_t *q2)
{
    return q2->last_insert_id;
}

static const char* q2_get_error(q2_t *q2)
{
    return q2->log;
}


module AP_MODULE_DECLARE_DATA q2_module;
static ap_dbd_t* (*dbd_fn)(request_rec*) = NULL;

typedef struct q2_rest_cfg_t {
    int pagination_ppg;
    const char *auth_params;
    const char *async_path;
} q2_rest_cfg_t;

typedef struct q2_rest_url_data_t {
    apr_pool_t *pool;
    char *async_id;
    apr_array_header_t *data;
    const char *server;
    int port;
} q2_rest_url_data_t;

static int q2_rest_valid_handler(request_rec *r, const char *hd)
{
    return strcmp(r->handler, hd) == 0;
}

static int q2_rest_valid_method(request_rec *r)
{
    return (r->method_number == M_GET || r->method_number == M_POST ||
            r->method_number == M_PUT || r->method_number == M_PATCH ||
            r->method_number == M_DELETE);
}

static int q2_rest_valid_content_type(request_rec *r)
{
    const char *ctype = apr_table_get(r->headers_in, "Content-Type");
    return (ctype != NULL && (strcmp(ctype, Q2_REST_CTYPE_TEXT) == 0 ||
                              strcmp(ctype, Q2_REST_CTYPE_TEXT_UTF8) == 0 ||
                              strcmp(ctype, Q2_REST_CTYPE_JSON) == 0 ||
                              strcmp(ctype, Q2_REST_CTYPE_JSON_UTF8) == 0 ||
                              strcmp(ctype, Q2_REST_CTYPE_FORM) == 0 ||
                              strcmp(ctype, Q2_REST_CTYPE_FORM_UTF8) == 0));
}

static int q2_rest_valid_accept(request_rec *r)
{
    const char *accept = apr_table_get(r->headers_in, "Accept");
    return (accept != NULL && (strcmp(accept, Q2_REST_ACCEPT_JSON) == 0 ||
                               strcmp(accept, Q2_REST_ACCEPT_JSON_UTF8)));
}

static const char* q2_rest_md5(apr_pool_t *mp, const char *s)
{
    const char *str = "";
    union {unsigned char chr[16]; uint32_t num[4];} digest;
    apr_md5_ctx_t md5;
    apr_md5_init(&md5);
    apr_md5_update(&md5, s, strlen(s));
    apr_md5_final(digest.chr, &md5);
    for (int i = 0; i < APR_MD5_DIGESTSIZE/4; i++) {
        str = apr_pstrcat(mp, str,
                          apr_psprintf(mp, "%08x", digest.num[i]), NULL);
    }
    return str;
}

static char* q2_rest_base64_encode(apr_pool_t *mp, const char *s)
{
    int s_l, b64_l;
    char *b64_s;
    if (s == NULL) return NULL;
    s_l = (int)strlen(s);
    b64_l = apr_base64_encode_len(s_l);
    b64_s = (char*)apr_palloc(mp, sizeof(char)*b64_l);
    if (b64_s == NULL) return NULL;
    apr_base64_encode(b64_s, s, s_l);
    return b64_s;
}

static const char* q2_rest_hmac(apr_pool_t *mp,
                                const uint8_t *k,
                                uint32_t k_len,
                                const uint8_t *s,
                                uint32_t s_len)
{
    apr_array_header_t *hash_ar;
    uint32_t hash_len = SHA256_DIGEST_SIZE;
    uint8_t hash[hash_len];
    unsigned char* res;
    res = HMAC(EVP_sha256(), k, k_len, s, s_len, hash, &hash_len);
    hash_ar = apr_array_make(mp, SHA256_DIGEST_SIZE, sizeof(const char*));
    for (int i = 0; i < hash_len; i++) {
        APR_ARRAY_PUSH(hash_ar, const char*) = apr_psprintf(mp, "%02x", res[i]);
    }
    return q2_join(mp, hash_ar, "");
}

static int q2_rest_authenticate(request_rec *r,
                                ap_dbd_t *dbd,
                                q2_rest_cfg_t *cfg,
                                char *auth,
                                char *date,
                                int *unauth)
{
    int er;
    const char *auth_data;
    const char *user;
    const char *nonce;
    const char *req_digest;
    const char *sql;
    const char *table;
    const char *usrcl;
    const char *pwdcl;
    const uint8_t *pwd;
    const char *hmac;
    const char *digest;
    const uint8_t *s;
    apr_array_header_t *auth_ar;
    apr_array_header_t *auth_data_ar;
    apr_array_header_t *dbd_data_ar;
    apr_array_header_t *pwd_res;
    char qry[] = "SELECT %s FROM %s where %s='%s'";
    if (auth == NULL || date == NULL || cfg->auth_params == NULL) return 1;
    *unauth = 1;
    q2_strip_spaces(date);
    auth_ar = q2_split(r->pool, auth, " ");
    if (auth_ar == NULL || auth_ar->nelts < 2) return 1;
    auth_data = APR_ARRAY_IDX(auth_ar, 1, const char*);
    if (auth_data == NULL) return 1;
    auth_data_ar = q2_split(r->pool, auth_data, ":");
    if (auth_data_ar == NULL || auth_data_ar->nelts < 3) return 1;
    user = APR_ARRAY_IDX(auth_data_ar, 0, const char*);
    nonce = APR_ARRAY_IDX(auth_data_ar, 1, const char*);
    req_digest = APR_ARRAY_IDX(auth_data_ar, 2, const char*);
    dbd_data_ar = q2_split(r->pool, cfg->auth_params, ":");
    if (dbd_data_ar == NULL) return 1;
    table = APR_ARRAY_IDX(dbd_data_ar, 0, const char*);
    if (table == NULL) return 1;
    usrcl = APR_ARRAY_IDX(dbd_data_ar, 1, const char*);
    if (usrcl == NULL) return 1;
    pwdcl = APR_ARRAY_IDX(dbd_data_ar, 2, const char*);
    if (pwdcl == NULL) return 1;
    sql = apr_psprintf(r->pool, qry, pwdcl, table, usrcl, user);
    if (sql == NULL) return 1;
    pwd_res = q2_dbd_select(r->pool, dbd->driver, dbd->handle, sql, &er);
    if (pwd_res == NULL || pwd_res->nelts <= 0) return 1;
    apr_table_t *pwd_tab = APR_ARRAY_IDX(pwd_res, 0, apr_table_t*);
    if (pwd_tab == NULL) return 1;
    pwd = (const uint8_t*)apr_table_get(pwd_tab, pwdcl);
    if (pwd == NULL) return 1;
    s = (const uint8_t*)apr_psprintf(r->pool, "%s+%s+%s+%s", r->method,
                                     r->unparsed_uri, date, nonce);
    if (s == NULL) return 1;
    hmac = q2_rest_hmac(r->pool, pwd, strlen((const char*)pwd), s,
                   strlen((const char*)s));
    if (hmac == NULL) return 1;
    digest = q2_rest_base64_encode(r->pool, hmac);
    if (digest == NULL) return 1;
    *unauth = strcmp(digest, req_digest) != 0;
    return 0;
}

static int q2_rest_authorized(request_rec *r,
                              ap_dbd_t *dbd,
                              q2_rest_cfg_t *cfg)
{
    const char *date = apr_table_get(r->headers_in, "Date");
    const char *authn = apr_table_get(r->headers_in, "Authentication");
    int unauthz = 1;
    if (authn != NULL && date != NULL && cfg->auth_params != NULL)
        q2_rest_authenticate(r, dbd, cfg, (char*)authn, (char*)date, &unauthz);
    return !unauthz;
}

static char* q2_rest_etag_gen(request_rec *r, const char *resource)
{
    return (char*)q2_rest_md5(r->pool, resource);
}

static int q2_rest_etag_match(apr_pool_t *mp,
                              const char *etag,
                              const char *res_etag)
{
    if (etag == NULL || res_etag == NULL) return FALSE;
    return (int)(strcmp(etag, res_etag) == 0);
}

static int q2_rest_want_match(request_rec *r, const char **etag)
{
    *etag = apr_table_get(r->headers_in, "If-Match");
    if (*etag != NULL) return TRUE;
    return FALSE;
}

static int q2_rest_want_none_match(request_rec *r, const char **etag)
{
    *etag = apr_table_get(r->headers_in, "If-None-Match");
    if (*etag != NULL) return TRUE;
    return FALSE;
}

static int q2_rest_range(request_rec *r, int *from, int *to)
{
    *from = 0;
    *to = 0;
    const char *range_v;
    apr_array_header_t *range_ar;
    apr_array_header_t *range_v_ar;
    const char *range = apr_table_get(r->headers_in, "Range");
    if (range == NULL) return FALSE;
    range_ar = q2_split(r->pool, range, "=");
    if (range_ar == NULL || range_ar->nelts < 2) return FALSE;
    range_v = APR_ARRAY_IDX(range_ar, 1, const char*);
    if (range_v == NULL) return FALSE;
    range_v_ar = q2_split(r->pool, range_v, "-");
    if (range_v_ar == NULL || range_ar->nelts < 2) return FALSE;
    *from = atoi(APR_ARRAY_IDX(range_v_ar, 0, const char*));
    *to = atoi(APR_ARRAY_IDX(range_v_ar, 1, const char*));
    *from = (*from) + 1;
    *to  = (*to) + 2;
    return *to > *from;
}

static int q2_rest_write_file(apr_pool_t *mp,
                              const char *fname,
                              const char *data)
{
    apr_status_t rv;
    apr_file_t *fh;
    apr_finfo_t finfo;
    int mode = APR_FOPEN_WRITE;
    rv = apr_stat(&finfo, fname, APR_FINFO_NORM, mp);
    if (rv != APR_SUCCESS) mode = APR_FOPEN_CREATE|mode;
    rv = apr_file_open(&fh, fname, mode, APR_OS_DEFAULT, mp);
    if (rv == APR_SUCCESS) {
        rv = apr_file_lock(fh, APR_FLOCK_EXCLUSIVE);
        if (rv == APR_SUCCESS) {
            apr_file_printf(fh, "%s", data);
            apr_file_unlock(fh);
        }
        apr_file_close(fh);
        return TRUE;
    }
    return FALSE;
}

static int q2_rest_file_read_char(apr_pool_t *mp, const char* fname, char *ch)
{
    apr_status_t rv;
    apr_file_t *fh;
    apr_finfo_t finfo;
    *ch = '\0';
    rv = apr_stat(&finfo, fname, APR_FINFO_NORM, mp);
    if (rv == APR_SUCCESS) {
        rv = apr_file_open(&fh, fname, APR_FOPEN_READ, APR_OS_DEFAULT, mp);
        if (rv == APR_SUCCESS) apr_file_getc(ch, fh);
        apr_file_close(fh);
        return TRUE;
    }
    return FALSE;
}

static const char* q2_rest_async_id(request_rec *r, const char *uri)
{
    const apr_strmatch_pattern *pattern;
    const char *async_p, *tmp;
    apr_array_header_t *arr;
    if (uri == NULL || strlen(uri) <= 0) return NULL;
    pattern = apr_strmatch_precompile(r->pool, "/async/", 1);
    if (pattern == NULL) return NULL;
    async_p = apr_strmatch(pattern, uri, strlen(uri));
    if (async_p == NULL) return NULL;
    arr = q2_split(r->pool, uri, "/");
    if (arr != NULL && arr->nelts > 0)
        tmp = APR_ARRAY_IDX(arr, arr->nelts-1, const char*);
    if (tmp == NULL) return NULL;
    return apr_pstrdup(r->pool, tmp);
}

static int q2_rest_async_save_data(request_rec *r,
                                   q2_rest_cfg_t *cfg,
                                   const char *data,
                                   const char **id)
{
    int rand_num;
    const char *ctype;
    const char *accept;
    const char *auth;
    const char *date;
    const char *fdata;
    const char *fname;
    ctype = apr_table_get(r->headers_in, "Content-Type");
    accept = apr_table_get(r->headers_in, "Accept");
    auth = apr_table_get(r->headers_in, "Authentication");
    date = apr_table_get(r->headers_in, "Date");
    if (auth == NULL || ctype == NULL || accept == NULL || date == NULL)
        return FALSE;
    *id = q2_rest_md5(r->pool, apr_psprintf(r->pool, "%s-%s-%" APR_TIME_T_FMT,
                                       auth, r->unparsed_uri,
                                       apr_time_now()));
    if (*id != NULL) {
        fname = apr_psprintf(r->pool, Q2_REST_ASYNC_FREQUEST,
                             cfg->async_path, *id);
        fdata = apr_psprintf(r->pool, Q2_REST_ASYNC_REQUEST, r->the_request,
                             r->server->server_hostname,
                             accept, ctype, *id, auth, date,
                             data == NULL ? "\0" : data);
        if (fname != NULL && fdata != NULL)
            if (q2_rest_write_file(r->pool, fname, fdata))
                return TRUE;
    }
    return FALSE;
}

static int q2_rest_async_save_status(request_rec *r,
                                     q2_rest_cfg_t *cfg,
                                     const char *id,
                                     const char *status)
{
    const char *fname;
    if (id != NULL) {
        fname = apr_psprintf(r->pool, Q2_REST_ASYNC_FSTATUS,
                             cfg->async_path, id);
        if (fname != NULL)
            if (q2_rest_write_file(r->pool, fname, status))
                return TRUE;
    }
    return FALSE;
}

static int q2_rest_async_get_status(request_rec *r,
                                    q2_rest_cfg_t *cfg,
                                    const char *id)
{
    char ch;
    const char *fname = NULL;
    if (id != NULL) {
        fname = apr_psprintf(r->pool, Q2_REST_ASYNC_FSTATUS,
                             cfg->async_path, id);
        if (q2_rest_file_read_char(r->pool, fname, &ch))
            return (int)atoi(apr_psprintf(r->pool, "%c", ch));
    }
    return 0;
}

static int q2_rest_async_remove_request(request_rec *r,
                                        q2_rest_cfg_t *cfg,
                                        const char *id)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    const char *fname;
    if (id != NULL) {
        fname = apr_psprintf(r->pool, Q2_REST_ASYNC_FREQUEST,
                             cfg->async_path, id);
        if (fname != NULL) {
            rv = apr_stat(&finfo, fname, APR_FINFO_NORM, r->pool);
            if (rv == APR_SUCCESS) apr_file_remove(fname, r->pool);
        }
    }
    return FALSE;
}

static int q2_rest_async_remove_status(request_rec *r, q2_rest_cfg_t *cfg,
                                const char *id)
{
    apr_status_t rv;
    apr_finfo_t finfo;
    const char *fname;
    if (id != NULL) {
        fname = apr_psprintf(r->pool, Q2_REST_ASYNC_FSTATUS,
                             cfg->async_path, id);
        if (fname != NULL) {
            rv = apr_stat(&finfo, fname, APR_FINFO_NORM, r->pool);
            if (rv == APR_SUCCESS) apr_file_remove(fname, r->pool);
        }
    }
    return FALSE;
}

static apr_table_t* q2_rest_request_formdata(request_rec *r)
{
    int rv;
    char *buffer;
    apr_off_t len;
    apr_size_t size;
    apr_table_t *retv;
    apr_array_header_t *pairs = NULL;
    rv = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
    if (rv != OK || !pairs) return NULL;
    if ((retv = apr_table_make(r->pool, pairs->nelts)) == NULL) return NULL;
    while (pairs && !apr_is_empty_array(pairs)) {
        ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t) len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        apr_table_setn(retv, apr_pstrdup(r->pool, pair->name), buffer);
    }
    return retv;
}

static apr_table_t* q2_rest_request_params(request_rec *r)
{
    apr_table_t *retv;
    if (r->method_number == M_POST) retv = q2_rest_request_formdata(r);
    else ap_args_to_table(r, &retv);
    if (retv == NULL || (apr_table_elts(retv))->nelts <= 0) return NULL;
    return retv;
}

static size_t q2_rest_request_rawdata(request_rec *r, const char **rbuf)
{
    int st;
    size_t size;
    *rbuf = NULL;
    if ((st = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) return 1;
    if (ap_should_client_block(r)) {
        char buf[HUGE_STRING_LEN];
        apr_off_t rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        *rbuf = (const char*)apr_pcalloc(r->pool, (apr_size_t)(length + 1));
        if (*rbuf == NULL) return 1;
        size = length;
        while ((len_read = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
            if((rpos + len_read) > length) rsize = length - rpos;
            else rsize = len_read;
            memcpy((char *) *rbuf + rpos, buf, (size_t) rsize);
            rpos += rsize;
        }
    }
    return size;
}

static int q2_rest_valid_data(request_rec *r, apr_table_t **params,
                              const char **raw, int *rawlen)
{
    *raw = NULL;
    *rawlen = 0;
    *params = NULL;
    if (r->method_number == M_PATCH) *rawlen = q2_rest_request_rawdata(r, raw);
    else *params = q2_rest_request_params(r);
    if (r->method_number == M_PUT && *params == NULL) return FALSE;
    if (r->method_number == M_PATCH)
        if (*raw == NULL || *rawlen <= 0) return FALSE;
    return TRUE;
}

static int q2_rest_prefer_minimal(request_rec *r)
{
    const char *prefer;
    if ((prefer = apr_table_get(r->headers_in, "Prefer")) != NULL)
        return strcmp(prefer, "return=minimal") == 0;
    return FALSE;
}

static const char* q2_hateoas(q2_t *q2)
{
    const char *l, *links_s, *attrs_s, *col, *opt, *rel, *rpk, *val;
    apr_array_header_t *links;
    apr_table_t *t, *result;
    if (q2->attributes == NULL) return NULL;
    links = apr_array_make(q2->pool, 0, sizeof(const char*));
    for (int i = 0; i < q2->attributes->nelts; i++) {
        t = APR_ARRAY_IDX(q2->attributes, i, apr_table_t*);
        if (t != NULL) {
            col = apr_table_get(t, "column_name");
            opt = apr_table_get(t, "column_options");
            rel = apr_table_get(t, "referenced_table");
            rpk = apr_table_get(t, "referenced_pk");
            if (col != NULL && opt != NULL && rel != NULL && rpk != NULL && strcmp(opt, "null")) {
                for (int j = 0; j < q2->results->nelts; j++) {
                    result = APR_ARRAY_IDX(q2->results, j, apr_table_t*);
                    if (result != NULL) {
                        val = apr_table_get(result, col);
                        if (val != NULL) {
                            l = apr_psprintf(q2->pool, "%s/%s;rel=\"%s\"", rel, val, rel);
                            APR_ARRAY_PUSH(links, const char*) = l;
                        }
                    }
                }
            }
        }
    }
    // attrs_s = q2->attributes == NULL
    //     ? NULL
    //     : q2_json_array(q2->pool, q2->attributes, Q2_TP_TABLE);
    // links_s = links == NULL
    //     ? NULL
    //     : q2_json_array(q2->pool, links, Q2_TP_STRNG);
    // return apr_psprintf(q2->pool, "{\"links\":%s,\"attributes\":%s}",
    //                     links_s == NULL ? "null" : links_s,
    //                     attrs_s == NULL ? "null" : attrs_s);
    return links == NULL
        ? NULL
        : q2_json_array(q2->pool, links, Q2_STRING);
}

static int q2_rest_request_handler(request_rec *r)
{
    ap_dbd_t *dbd;
    apr_status_t rv;
    q2_rest_cfg_t *cfg;
    q2_t *q2;
    int rawlen = 0;
    const char *rawdata = NULL;
    apr_table_t *params = NULL;
    const char *er;
    const char *out;

    dbd_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    dbd = dbd_fn(r);
    cfg = (q2_rest_cfg_t*)ap_get_module_config(r->server->module_config,
                                               &q2_module);

    if (!q2_rest_valid_handler(r, "q2")) return DECLINED;
    if (!q2_rest_valid_method(r)) return HTTP_METHOD_NOT_ALLOWED;
    if (!q2_rest_valid_content_type(r)) return HTTP_UNSUPPORTED_MEDIA_TYPE;
    if (!q2_rest_valid_accept(r)) return HTTP_NOT_ACCEPTABLE;
    if (!q2_rest_authorized(r, dbd, cfg)) return HTTP_UNAUTHORIZED;

    if (cfg->async_path != NULL) {
        const char *async_id = q2_rest_async_id(r, r->unparsed_uri);
        if (async_id != NULL) {
            int async_status = q2_rest_async_get_status(r, cfg, async_id);
            if (!async_status) return HTTP_NOT_FOUND;
            if (async_status == atoi(Q2_REST_ASYNC_DONE)) {
                ap_rprintf(r, Q2_REST_ASYNC_STATUS, "Completed.");
                q2_rest_async_remove_status(r, cfg, async_id);
            } else {
                ap_rprintf(r, Q2_REST_ASYNC_STATUS, "In progress...");
            }
            return OK;
        }
    }

    if (!q2_rest_valid_data(r, &params, &rawdata, &rawlen))
        return HTTP_BAD_REQUEST;

    if (r->method_number != M_GET) {
        const char *async = apr_table_get(r->headers_in, Q2_REST_ASYNC_HEADER);
        if (async != NULL && (strcmp(async, "1") == 0)) {
            const char *query_string = NULL;
            if (r->method_number == M_PUT)
                if (r->parsed_uri.query != NULL)
                    query_string = apr_pstrdup(r->pool, r->parsed_uri.query);
            if (r->method_number == M_POST)
                if (params != NULL)
                    query_string = q2_table_to_args(r->pool, params);
            const char *async_id = NULL;
            if (q2_rest_async_save_data(r, cfg,
                                        query_string == NULL
                                            ? rawdata
                                            : query_string,
                                        &async_id)) {
                if (q2_rest_async_save_status(r, cfg, async_id, Q2_REST_ASYNC_PROGRESS)) {
                    const char *loc = apr_psprintf(r->pool,
                                                   Q2_REST_ASYNC_URI, async_id);
                    apr_table_set(r->headers_out, "Location", loc);
                    return OK;
                }
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    q2 = q2_initialize(r->pool);
    if (q2 == NULL) {
        ap_rprintf(r, "q2_initialize() error\n");
        return OK;
    }
    q2_set_request_rec(q2, r);
    q2_set_dbd(q2, dbd->driver, dbd->handle);
    q2_set_method(q2, r->method);
    q2_set_uri(q2, r->unparsed_uri);
    q2_set_params(q2, params);
    q2_set_rawdata(q2, rawdata, rawlen);
    q2_set_ppg(q2, cfg->pagination_ppg);
    rv = q2_acquire(q2);
    if (rv != APR_SUCCESS) {
        if ((er = q2_get_error(q2)) != NULL) ap_rprintf(r, "Error: %s\n\n", er);
        else ap_rprintf(r, "An error occurred.\n\n");
        return OK;
    }

    if (r->method_number != M_GET) {
        const char *async = apr_table_get(r->headers_in, Q2_REST_ASYNC_HEADER);
        if (async != NULL && strcmp(async, "1"))
            if (q2_rest_async_save_status(r, cfg, async, "2"))
                return OK;
    }

    const char *id, *loc;
    if (r->method_number != M_GET) {
        if (q2_rest_prefer_minimal(r)) {
            if (r->method_number == M_POST) {
                if ((id = q2_get_last_id(q2)) != NULL) {
                    loc = apr_psprintf(r->pool, "%s/%s", r->unparsed_uri, id);
                    apr_table_set(r->headers_out, "Location", loc);
                    return OK;
                }
            }
            return HTTP_NO_CONTENT;
        }
    }

    int range_from, range_to;
    const char *partial = NULL;
    if (r->method_number == M_GET) {
        if (q2_rest_range(r, &range_from, &range_to)) {
            if (q2_get_result(q2, 0, NULL, &out)) {
                if (out != NULL) {
                    ap_rprintf(r, "%s", out);
                    return OK;
                }
            }
        }
    }

    out = q2_encode_json(q2);

    const char *hateoas = q2_hateoas(q2);
    const char *payload = apr_psprintf(r->pool,
                                       "{\"body\":%s,\"_links\":%s}",
                                       out,
                                       hateoas == NULL
                                            ? "null"
                                            : hateoas);

    const char *res_etag = NULL, *etag = NULL;
    if (r->method_number == M_GET) {
        if (q2_contains_single_entity(q2)) {
            res_etag = q2_rest_etag_gen(r, payload);
            apr_table_set(r->headers_out, "ETag",
                          apr_psprintf(r->pool, "W/\"%s\"", res_etag));
            if (q2_rest_want_match(r, &etag)) {
                if (!q2_rest_etag_match(r->pool, etag, res_etag)) {
                    return HTTP_NOT_MODIFIED;
                }
            }
            if (q2_rest_want_none_match(r, &etag)) {
                if (q2_rest_etag_match(r->pool, etag, res_etag)) {
                    return HTTP_NOT_MODIFIED;
                }
            }
        }
    }


    ap_rprintf(r, "%s", payload);
    return OK;
}

static apr_status_t q2_rest_do_connect(apr_socket_t **sock,
                                       q2_rest_url_data_t *d)
{
    apr_sockaddr_t *sa;
    apr_socket_t *s;
    apr_status_t rv;
    rv = apr_sockaddr_info_get(&sa, d->server, APR_INET, d->port, 0, d->pool);
    if (rv != APR_SUCCESS) return rv;
    rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, d->pool);
    if (rv != APR_SUCCESS) return rv;
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set(s, Q2_REST_WD_SOCK_TIMEOUT);
    rv = apr_socket_connect(s, sa);
    if (rv != APR_SUCCESS) return rv;
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
    apr_socket_timeout_set(s, Q2_REST_WD_SOCK_TIMEOUT);
    *sock = s;
    return APR_SUCCESS;
}

static apr_status_t q2_rest_do_client_task(apr_socket_t *sock,
                                           const char *data,
                                           q2_rest_url_data_t *d)
{
    apr_status_t rv;
    apr_size_t len = strlen(data);
    rv = apr_socket_send(sock, data, &len);
    if (rv != APR_SUCCESS) return rv;
    return rv;
}

static void *q2_rest_thread(void *t_data)
{
    apr_status_t rv;
    apr_socket_t *s;
    q2_rest_url_data_t *d;
    const char *data, *tmp;
    apr_time_t inizio = apr_time_now();
    apr_sleep(15 * Q2_REST_WD_SECOND);
    d = (q2_rest_url_data_t *)t_data;
    data = "";
    for (int i = 0; i < d->data->nelts; i++) {
        tmp = APR_ARRAY_IDX(d->data, i, const char *);
        if (tmp != NULL) data = apr_pstrcat(d->pool, data, tmp, NULL);
    }
    rv = q2_rest_do_connect(&s, d);
    if (rv != APR_SUCCESS) goto end;
    rv = q2_rest_do_client_task(s, data, d);
    if (rv != APR_SUCCESS) goto end;
    apr_time_t fine = apr_time_now();
end:
    apr_socket_close(s);
    apr_pool_destroy(d->pool);
    pthread_exit(0);
}

static int q2_rest_aysnc_get_proc(q2_rest_cfg_t *cfg, apr_pool_t *mp)
{
    const char *dirpath;
    const char *fname;
    pthread_t tid;
    apr_status_t rv;
    apr_pool_t *pool;
    apr_dir_t *dir;
    apr_finfo_t dirent;
    apr_file_t *fh;
    q2_rest_url_data_t *d;
    if ((rv = apr_pool_create(&pool, mp)) == APR_SUCCESS) {
        dirpath = apr_pstrdup(pool, cfg->async_path);
        char tmp[256];
        if ((rv = apr_dir_open(&dir, dirpath, pool)) == APR_SUCCESS) {
            while ((apr_dir_read(&dirent, Q2_REST_WD_DIROPT, dir)) == APR_SUCCESS) {
                if (dirent.filetype == APR_REG) {
                    if (dirent.name[0] == '_') continue;
                    fname = apr_pstrcat(pool, dirpath, "/", dirent.name, NULL);
                    rv = apr_file_open(&fh, fname, APR_FOPEN_READ, APR_OS_DEFAULT, pool);
                    if (rv == APR_SUCCESS) {
                        apr_pool_t *t_pool;
                        rv = apr_pool_create(&t_pool, NULL);
                        if (rv == APR_SUCCESS) {
                            d = (q2_rest_url_data_t*)apr_palloc(t_pool, sizeof(q2_rest_url_data_t));
                            if (d != NULL) {
                                d->pool = t_pool;
                                d->server = apr_pstrdup(t_pool, Q2_REST_WD_HOST);
                                d->port = Q2_REST_WD_PORT;
                                d->async_id = (char*)apr_pstrdup(t_pool, dirent.name);
                                d->data = apr_array_make(t_pool, 6, sizeof(const char*));
                                while ((rv = apr_file_eof(fh)) == APR_SUCCESS) {
                                    if ((rv = apr_file_gets(tmp, 256, fh)) == APR_SUCCESS) {
                                        APR_ARRAY_PUSH(d->data, const char*) = apr_pstrdup(t_pool, tmp);
                                    }
                                }
                            }
                        }
                        apr_file_close(fh);
                        apr_file_remove(fname, pool);
                        pthread_create(&tid, NULL, q2_rest_thread, (void*)d);
                    }
                }
            }
            apr_dir_close(dir);
        }
        apr_pool_destroy(pool);
    }
    return 0;
}

static int q2_rest_async_monitor(q2_rest_cfg_t *cfg, apr_pool_t *p)
{
    q2_rest_aysnc_get_proc(cfg, p);
    return OK;
}

static int q2_rest_async_init(server_rec *s, const char *name, apr_pool_t *pool)
{
    q2_rest_cfg_t *cfg = ap_get_module_config(s->module_config, &q2_module);
    return OK;
}

static int q2_rest_async_exit(server_rec *s, const char *name, apr_pool_t *pool)
{
    return OK;
}

static int q2_rest_async_step(server_rec *s, const char *name, apr_pool_t *pool)
{
    q2_rest_cfg_t *cfg = ap_get_module_config(s->module_config, &q2_module);
    if (cfg->async_path == NULL || strcmp(name, AP_WATCHDOG_SINGLETON))
        return OK;
    return q2_rest_async_monitor(cfg, pool);
}

static int q2_rest_async_need(server_rec *s,
                              const char *name,
                              int parent,
                              int sngl)
{
    q2_rest_cfg_t *cfg = ap_get_module_config(s->module_config, &q2_module);
    if (cfg->async_path != NULL && sngl && !strcmp(name, AP_WATCHDOG_SINGLETON))
        return OK;
    return DECLINED;
}

static void q2_rest_register_hooks(apr_pool_t *p)
{
    ap_hook_watchdog_need(q2_rest_async_need, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_init(q2_rest_async_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_step(q2_rest_async_step, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_watchdog_exit(q2_rest_async_exit, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_handler(q2_rest_request_handler, NULL, NULL, APR_HOOK_LAST);
}

static void *q2_rest_create_config(apr_pool_t *p, server_rec *s)
{
    q2_rest_cfg_t *cfg = (q2_rest_cfg_t*)apr_pcalloc(p, sizeof(q2_rest_cfg_t));
    cfg->async_path = NULL;
    cfg->auth_params = NULL;
    cfg->pagination_ppg = 0;
    return cfg;
}

static const char *q2_rest_cmd_auth(cmd_parms *cmd, void *dconf, const char *auth)
{
    q2_rest_cfg_t *cfg = (q2_rest_cfg_t*)ap_get_module_config(cmd->server->module_config,
                                                    &q2_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_CONTEXT);
    if (err != NULL) return err;
    if (cfg->auth_params == NULL) cfg->auth_params = auth;
    return NULL;
}

static const char *q2_rest_cmd_async(cmd_parms *cmd, void *dconf, const char *async)
{
    q2_rest_cfg_t *cfg = (q2_rest_cfg_t*)ap_get_module_config(cmd->server->module_config,
                                                    &q2_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_CONTEXT);
    if (err != NULL) return err;
    if (cfg->async_path == NULL) cfg->async_path = async;
    return NULL;
}

static const char *q2_rest_cmd_ppg(cmd_parms *cmd, void *dconf, const char *ppg)
{
    q2_rest_cfg_t *cfg = (q2_rest_cfg_t*)ap_get_module_config(cmd->server->module_config,
                                                    &q2_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_CONTEXT);
    if (err != NULL) return err;
    cfg->pagination_ppg = atoi(ppg);
    return NULL;
}

static const command_rec q2_rest_cmds[] = {
    AP_INIT_TAKE1("Q2DBDAuthParams", q2_rest_cmd_auth, NULL, RSRC_CONF,
                  "Enable HMAC authentication"),
    AP_INIT_TAKE1("Q2AsyncPath", q2_rest_cmd_async, NULL, RSRC_CONF,
                  "Enable/Disable asynchronous operations (0=disabled)"),
    AP_INIT_TAKE1("Q2PaginationPPG", q2_rest_cmd_ppg, NULL, RSRC_CONF,
                  "Enable/Disable pagination (0=disabled)"),
    {NULL}
};

AP_DECLARE_MODULE(q2) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    q2_rest_create_config,
    NULL,
    q2_rest_cmds,
    q2_rest_register_hooks
};

