#include "ap_mmn.h" /* For MODULE_MAGIC_NUMBER */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "http_request.h" /* for ap_hook_(check_user_id | auth_checker)*/
#include "ap_compat.h"
#include "apr_strings.h"
#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_general.h"

#include "redis.h"

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>

#define APR_ARRAY_FOREACH_INIT() apr_table_entry_t *apr_foreach_elts;int apr_foreach_i;char *key,*val

#define APR_ARRAY_FOREACH_OPEN(arr, key, val) \
	{ \
		apr_foreach_elts = (apr_table_entry_t *) arr->elts; \
		for(apr_foreach_i = 0; apr_foreach_i < arr->nelts; apr_foreach_i++) { \
			key = apr_foreach_elts[apr_foreach_i].key;       \
			val = apr_foreach_elts[apr_foreach_i].val;

#define APR_ARRAY_FOREACH_CLOSE() \
		} \
	}

/*
 * structure to hold the configuration details for the request
 */
typedef struct {
	redis_t redis;
	char *host;                 /* host name of redis server */
	int  port;                  /* port number of redis server */
	char *auth;                 /* auth for connect to redis server */
	int database;               /* redis database index */
	char *key;                  /* redis store to key */
	int  enable;                /* do we bother trying to auth at all? */
	long int insertId;               /* insert after dumpId for value */
	apr_time_t currentTime;
	apr_time_t executeTime;
	apr_array_header_t *rules;	/* dump rule array */
} dump_redis_config_rec;

/*
 * structure to dump rule
 */
typedef struct {
	char *pattern;
	ap_regex_t *regexp;
} rule_entry;

static const char dump_redis_filter_name[] = "dump_redis";

static apr_status_t dump_redis_db_cleanup (void *data) {
	dump_redis_config_rec *m = data;
	char keybuf[256];

	redis_close(&m->redis);

	return 0;
}

static bool open_db_handle(request_rec *r, dump_redis_config_rec *m) {
	if(m->redis.fp) {
		if(redis_ping(&m->redis)) return true;

		redis_close(&m->redis);
	}

	if(!redis_init(&m->redis, 0)) return false;

	if(!redis_connect(&m->redis, m->host, m->port)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(connect): %s", strerror(errno));
		goto err;
	}
	
	if(m->auth && !redis_auth(&m->redis, m->auth)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(auth): %s", redis_error(&m->redis));
		goto err;
	}

	if(!redis_select(&m->redis, m->database)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(select): %s", redis_error(&m->redis));
		goto err;
	}

	if(m->insertId <= 0) {
		char keybuf[256];

		snprintf(keybuf, sizeof(keybuf), "%s:incr", m->key ? m->key : "apacheDump");

		if(!redis_incrby(&m->redis, keybuf, 1, &m->insertId)) {
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(incrby): %s", redis_error(&m->redis));
			goto err;
		}
	}

	apr_pool_cleanup_register(r->pool, (void *)m, dump_redis_db_cleanup, apr_pool_cleanup_null);

	return true;

err:
	redis_close(&m->redis);
	return false;
}

static void *create_dump_redis_dir_config (apr_pool_t *p, char *d)
{
	dump_redis_config_rec *m = apr_pcalloc(p, sizeof(dump_redis_config_rec));
	if(!m) return NULL;  /* failure to get memory is a bad thing */

	memset(&m->redis, 0, sizeof(redis_t));

	/* default values */
	m->host = "127.0.0.1";
	m->port = 6379;
	m->auth = NULL;
	m->database = 0;
	m->key = NULL;
	m->enable = false;     /* not enable on by default */
	m->insertId = 0;
	m->rules = apr_array_make(p, 20, sizeof(rule_entry));
	m->currentTime=0;
	m->executeTime=0;

	return (void *)m;
}

static const char *dump_redis_rule(cmd_parms *cmd, void *m_, int argc, char *const argv[]) {
	dump_redis_config_rec *m = m_;
	rule_entry *rule;
	int i;

	for(i=0; i<argc; i++) {
		rule = apr_array_push(m->rules);
		rule->regexp = ap_pregcomp(cmd->pool, argv[i], AP_REG_EXTENDED);
		if(rule->regexp == NULL) return "Regular expression could not be compiled.";
		rule->pattern = argv[i];
	}

	return NULL;
}

static command_rec dump_redis_cmds[] = {
	AP_INIT_TAKE1("DumpRedisHost", ap_set_string_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, host), OR_FILEINFO, "redis server host name"),
	AP_INIT_TAKE1("DumpRedisPort", ap_set_int_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, port), OR_FILEINFO, "redis server port number"),
	AP_INIT_TAKE1("DumpRedisAuth", ap_set_string_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, auth), OR_FILEINFO, "redis server auth"),
	AP_INIT_TAKE1("DumpRedisDatabase", ap_set_int_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, database), OR_FILEINFO, "redis database index"),
	AP_INIT_TAKE1("DumpRedisKey", ap_set_string_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, key), OR_FILEINFO, "redis data store to key prefix"),
	AP_INIT_FLAG("DumpRedisEnable", ap_set_flag_slot, (void *) APR_OFFSETOF(dump_redis_config_rec, enable), OR_FILEINFO, "enable redis dump filter"),
	AP_INIT_TAKE_ARGV("DumpRedisRule", dump_redis_rule, NULL, OR_FILEINFO, "Controls what individual directives can be configured by per-directory config files"),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA dump_redis_module;

char *strtime_r(time_t sec, int usec, char *buf, int buflen) {
	struct tm tm;
	localtime_r(&sec, &tm);

	snprintf(buf, buflen, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
		tm.tm_year + 1900, tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		usec
	);
}

char *nowtime_r(char *buf, int buflen) {
	struct timeval tv = {0, 0};

	gettimeofday(&tv, NULL);

	strtime_r(tv.tv_sec, tv.tv_usec, buf, buflen);

	return buf;
}

static bool dump_redis_record_full_and_response(request_rec *r, dump_redis_config_rec *m) {
	const apr_array_header_t *arr;
	char *requestHeader, *responseHeader, *ptr, *client_ip;
	unsigned long requestHeaderLength=0, responseHeaderLength=0;
	unsigned long uri_len, file_len;
	unsigned long method_len;
	unsigned long client_ip_len;
	APR_ARRAY_FOREACH_INIT();
	char keybuf[256];
	struct timeval tv = {0, 0};
	char requestTime[32], createTime[32];

	strtime_r(apr_time_sec(r->request_time), r->request_time % 1000000, requestTime, sizeof(requestTime));

	// get request header info
	arr = apr_table_elts(r->headers_in);
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
	if(!val) val = "";
	requestHeaderLength+=3;
	requestHeaderLength+=strlen(key);
	requestHeaderLength+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	requestHeader = (char *) apr_palloc(r->pool, requestHeaderLength + 1);
	ptr = requestHeader;
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
	sprintf(ptr, "%s: %s\n", key, val);
	ptr+=3;
	ptr+=strlen(key);
	ptr+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	// get response header info
	arr = apr_table_elts(r->headers_out);
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
	if(!val) val = "";
	responseHeaderLength+=3;
	responseHeaderLength+=strlen(key);
	responseHeaderLength+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	responseHeader = (char *) apr_palloc(r->pool, responseHeaderLength + 1);
	ptr = responseHeader;
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
	sprintf(ptr, "%s: %s\n", key, val);
	ptr+=3;
	ptr+=strlen(key);
	ptr+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	client_ip = (char*) apr_table_get(r->headers_in, "X-Forwarded-For");
	if(client_ip) {
		if(ptr = strchr(client_ip, ',')) {
			client_ip_len = ptr-client_ip;
		} else {
			client_ip_len = strlen(client_ip);
		}
	} else {
		client_ip = r->useragent_ip?r->useragent_ip:"127.0.0.1";
		client_ip_len = strlen(client_ip);
	}

	snprintf(keybuf, sizeof(keybuf), "%s:%ld", m->key ? m->key : "apacheDump", m->insertId);

	gettimeofday(&tv, NULL);
	strtime_r(tv.tv_sec, tv.tv_usec, createTime, sizeof(createTime));

	if(!redis_send(&m->redis, "sssssdsssssssssdsSsSsSsssfssssssss", "hset", keybuf,
		"scheme", ap_http_scheme(r),
		"port", r->server->addrs->host_port,
		"protocol", r->protocol,
		"url", r->unparsed_uri,
		"method", r->method,
		"requestTime", requestTime,
		"responseCode", r->status,
		"requestHeader", requestHeader, requestHeaderLength,
		"responseHeader", responseHeader, responseHeaderLength,
		"ip", client_ip, client_ip_len,
		"file", r->uri,
		"runTime", (float) (m->currentTime - m->executeTime - r->request_time) / 1000000.0f,
		"createTime", createTime,
		"contentType", (r->content_type ? r->content_type : apr_table_get(r->headers_out, "Content-Type")),
		"contentEncoding", (r->content_encoding ? r->content_encoding : apr_table_get(r->headers_out, "Content-Encoding")),
		"filename", r->filename
	)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(hset send): %s", redis_error(&m->redis));
		return false;
	}
	if(!redis_recv(&m->redis, REDIS_FLAG_INT)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(hset recv): %s", redis_error(&m->redis));
		return false;
	}

	return true;
}

static void dump_redis_record_post_or_response(request_rec *r, dump_redis_config_rec *m, bool is_post, char *buffer, int buffer_length) {
	char keybuf[256];

	snprintf(keybuf, sizeof(keybuf), "%s:%ld:%s", m->key ? m->key : "apacheDump", m->insertId, is_post ? "post" : "response");

	if(!redis_send(&m->redis, "ssS", "append", keybuf, buffer, buffer_length)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(append send): %s", redis_error(&m->redis));
		return;
	}
	if(!redis_recv(&m->redis, REDIS_FLAG_INT)) {
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(append recv): %s", redis_error(&m->redis));
		return;
	}
}

static bool dump_redis_record_insert_id(request_rec *r, dump_redis_config_rec *m) {
	if(!redis_send(&m->redis, "ssD", "rpush", m->key ? m->key : "apacheDump", m->insertId)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(rpush send): %s", redis_error(&m->redis));
		return false;
	}

	if(!redis_recv(&m->redis, REDIS_FLAG_INT)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "REDIS ERROR(rpush recv): %s", redis_error(&m->redis));
		return false;
	}

	return true;
}

static void dump_redis_record(request_rec *r, dump_redis_config_rec *sec, bool is_post, char *buffer, apr_size_t len) {
	sec->currentTime = apr_time_now();
	if(open_db_handle(r,sec)) dump_redis_record_post_or_response(r, sec, is_post, buffer, len);
	sec->executeTime += (apr_time_now() - sec->currentTime);
}

static int dump_redis_is_filter(request_rec *r, dump_redis_config_rec *sec) {
	rule_entry *rule, *rules = (rule_entry *) sec->rules->elts;
	int flag = 0, i;
	ap_regmatch_t regm[AP_MAX_REG_MATCH];

	for(i = 0; i < sec->rules->nelts; ++i) {
		rule = &rules[i];

		if(!ap_regexec(rule->regexp, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
			flag = 1;
			break;
		}
	}
	
	return i==0 || flag;
}

static int dump_redis_log_transaction(request_rec *r) {
	dump_redis_config_rec *m = (dump_redis_config_rec *)ap_get_module_config (r->per_dir_config, &dump_redis_module);

	if(!open_db_handle(r,m)) goto end;
	
	if(!dump_redis_record_full_and_response(r, m)) goto end;
	if(!dump_redis_record_insert_id(r, m)) goto end;

end:
	return OK;
}

static void dump_redis_insert_filter (request_rec *r) {
	dump_redis_config_rec *sec = (dump_redis_config_rec *)ap_get_module_config (r->per_dir_config, &dump_redis_module);

	if(!sec->enable)
		return;

	if(dump_redis_is_filter(r, sec)) {
		ap_add_input_filter(dump_redis_filter_name, NULL, r, r->connection);
		ap_add_output_filter(dump_redis_filter_name, NULL, r, r->connection);
	}
}

static int dump_redis_input_filter (ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	dump_redis_config_rec *sec = (dump_redis_config_rec *)ap_get_module_config (r->per_dir_config, &dump_redis_module);

	apr_bucket *b,*bh;
	apr_size_t len = 0;

	apr_bucket_brigade *ctx;

	int ret;
	char *buffer = NULL, *buf;

	if(!(ctx = f->ctx)) {
		f->ctx = ctx = apr_brigade_create(r->pool, c->bucket_alloc);
	}

	if(APR_BRIGADE_EMPTY(ctx)) {
		ret = ap_get_brigade(f->next, ctx, mode, block, readbytes);

		if(mode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
			return ret;
	}

	while(!APR_BRIGADE_EMPTY(ctx)) {
		b = APR_BRIGADE_FIRST(ctx);

		if(APR_BUCKET_IS_EOS(b)) {
			APR_BUCKET_REMOVE(b);
			APR_BRIGADE_INSERT_TAIL(bb, b);
			break;
		}

		ret = apr_bucket_read(b, (const char **) &buffer, &len, block);
		if(ret != APR_SUCCESS) return ret;

		if(len > 0) dump_redis_record(r, sec, true, buffer, len);

		buf = apr_bucket_alloc(len, c->bucket_alloc);
		memcpy(buf,buffer,len);

		bh = apr_bucket_heap_create(buf, len, apr_bucket_free, c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, bh);
		apr_bucket_delete(b);
	}

	return APR_SUCCESS;
}

static int dump_redis_output_filter (ap_filter_t *f, apr_bucket_brigade *bb) {
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	dump_redis_config_rec *sec = (dump_redis_config_rec *)ap_get_module_config (r->per_dir_config, &dump_redis_module);

	apr_bucket *b,*be,*bh;
	apr_bucket_brigade *ob;
	apr_size_t len = 0;

	int ret;
	char *buffer = NULL, *buf;

	ob = apr_brigade_create(r->pool, c->bucket_alloc);

	for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
		if(APR_BUCKET_IS_EOS(b)) {
			apr_bucket *be=apr_bucket_eos_create(c->bucket_alloc);
			APR_BRIGADE_INSERT_TAIL(ob,be);
			continue;
		}
		ret = apr_bucket_read(b, (const char **) &buffer, &len, APR_BLOCK_READ);
		if(ret != APR_SUCCESS) return ret;

		if(len > 0) dump_redis_record(r, sec, false, buffer, len);

		buf = apr_bucket_alloc(len, c->bucket_alloc);
		memcpy(buf, buffer, len);

		bh = apr_bucket_heap_create(buf, len, apr_bucket_free, c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(ob,bh);
	}
	apr_brigade_cleanup(bb);

	return ap_pass_brigade(f->next,ob);
}

static void dump_redis_register_hooks(apr_pool_t *p) {
	ap_hook_log_transaction(dump_redis_log_transaction,NULL,NULL,APR_HOOK_FIRST);
	ap_hook_insert_filter(dump_redis_insert_filter, NULL, NULL, APR_HOOK_LAST);
	ap_register_input_filter(dump_redis_filter_name, dump_redis_input_filter, NULL, AP_FTYPE_RESOURCE);
	ap_register_output_filter(dump_redis_filter_name, dump_redis_output_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA dump_redis_module = {
	STANDARD20_MODULE_STUFF,
	create_dump_redis_dir_config, /* dir config creater */
	NULL,       /* dir merger --- default is to override */
	NULL,       /* server config */
	NULL,       /* merge server config */
	dump_redis_cmds,    /* command apr_table_t */
	dump_redis_register_hooks  /* register hooks */
};
