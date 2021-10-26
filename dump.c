#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <zlib.h>

#include "redis.h"

volatile bool is_running = true;

void sig_handle(int sig) {
	is_running = false;
}

typedef struct _php_zlib_buffer {
	char *data;
	char *aptr;
	size_t used;
	size_t free;
	size_t size;
} php_zlib_buffer;

#define PHP_ZLIB_ENCODING_RAW		-0xf
#define PHP_ZLIB_ENCODING_GZIP		0x1f
#define PHP_ZLIB_ENCODING_DEFLATE	0x0f
#define PHP_ZLIB_ENCODING_ANY		0x2f

static inline int php_zlib_inflate_rounds(z_stream *Z, size_t max, char **buf, size_t *len)
{
	int status, round = 0;
	php_zlib_buffer buffer = {NULL, NULL, 0, 0, 0};

	*buf = NULL;
	*len = 0;

	buffer.size = (max && (max < Z->avail_in)) ? max : Z->avail_in;

	do {
		if ((max && (max <= buffer.used)) || !(buffer.aptr = realloc(buffer.data, buffer.size))) {
			status = Z_MEM_ERROR;
		} else {
			buffer.data = buffer.aptr;
			Z->avail_out = buffer.free = buffer.size - buffer.used;
			Z->next_out = (Bytef *) buffer.data + buffer.used;
			status = inflate(Z, Z_NO_FLUSH);

			buffer.used += buffer.free - Z->avail_out;
			buffer.free = Z->avail_out;
			buffer.size += (buffer.size >> 3) + 1;
		}
	} while ((Z_BUF_ERROR == status || (Z_OK == status && Z->avail_in)) && ++round < 100);

	if (status == Z_STREAM_END) {
		buffer.data = realloc(buffer.data, buffer.used + 1);
		buffer.data[buffer.used] = '\0';
		*buf = buffer.data;
		*len = buffer.used;
	} else {
		if (buffer.data) {
			free(buffer.data);
		}
		/* HACK: See zlib/examples/zpipe.c inf() function for explanation. */
		/* This works as long as this function is not used for streaming. Required to catch very short invalid data. */
		status = (status == Z_OK) ? Z_DATA_ERROR : status;
	}
	return status;
}

static voidpf php_zlib_alloc(voidpf opaque, uInt items, uInt size) {
	return (voidpf) calloc(items, size);
}

static void php_zlib_free(voidpf opaque, voidpf address) {
	free((void*)address);
}

static bool php_zlib_decode(const char *in_buf, size_t in_len, char **out_buf, size_t *out_len, int encoding, size_t max_len) {
	int status = Z_DATA_ERROR;
	z_stream Z;

	memset(&Z, 0, sizeof(z_stream));
	Z.zalloc = php_zlib_alloc;
	Z.zfree = php_zlib_free;

	if (in_len) {
retry_raw_inflate:
		status = inflateInit2(&Z, encoding);
		if (Z_OK == status) {
			Z.next_in = (Bytef *) in_buf;
			Z.avail_in = in_len + 1; /* NOTE: data must be zero terminated */

			switch (status = php_zlib_inflate_rounds(&Z, max_len, out_buf, out_len)) {
				case Z_STREAM_END:
					inflateEnd(&Z);
					return true;

				case Z_DATA_ERROR:
					/* raw deflated data? */
					if (PHP_ZLIB_ENCODING_ANY == encoding) {
						inflateEnd(&Z);
						encoding = PHP_ZLIB_ENCODING_RAW;
						goto retry_raw_inflate;
					}
			}
			inflateEnd(&Z);
		}
	}

	*out_buf = NULL;
	*out_len = 0;

	fprintf(stderr, "zlib error: %s", zError(status));
	return false;
}

bool redis_lpop_int(redis_t *redis, const char *key, long int *value) {
	if(!redis_send(redis, "ss", "lpop", key)) return false;
	if(!redis_recv(redis, REDIS_FLAG_BULK)) return false;
	
	if(redis->data.sz > 0) *value = strtol(redis->data.str, NULL, 10);
	else *value = 0;

	return true;
}

double microtime() {
	struct timeval tv = {0, 0};

	gettimeofday(&tv, NULL);
	
	return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0f;
}

int main(int argc, const char *argv[]) {
	const char *host = "127.0.0.1";
	int port = 6379;
	const char *auth = "";
	int database = 0;
	redis_t redis;
	int opt;
	int status = EXIT_SUCCESS;
	int flag = 0, i;
	char *key = "apacheDump";
	char keybuf[256];
	long int nextId = 0;
	char *str, *encoding = NULL;
	int size, exists;
	double t, t2, t3;
	const char *color_red = "\033[31m";
	const char *color_green = "\033[32m";
	const char *color_yellow = "\033[33m";
	const char *color_cls = "\033[0m";

	while((opt = getopt(argc, (char**) argv, "h:p:a:n:k:vd?")) != -1) {
		switch(opt) {
			case 'h':
				host = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'a':
				auth = optarg;
				break;
			case 'n':
				database = atoi(optarg);
				break;
			case 'k':
				key = optarg;
				break;
			case 'v':
				printf("%s\n", REDIS_VERSION);
				return EXIT_SUCCESS;
			case 'd':
				flag |= REDIS_FLAG_DEBUG;
				break;
			default:
				goto usage;
		}
	}

	if(!redis_init(&redis, flag)) return EXIT_FAILURE;
	if(!redis_connect(&redis, host, port)) goto end;
	if(*auth && !redis_auth(&redis, auth)) goto end;
	if(!redis_select(&redis, database)) goto end;

	if(!isatty(1)) {
		color_red = color_green = color_yellow = color_cls = "";
	}

	signal(SIGINT, sig_handle);
	signal(SIGTERM, sig_handle);

	t = microtime();
	while(is_running) {
		if(!redis_lpop_int(&redis, key, &nextId)) goto end;
		
		if(nextId <= 0) {
			usleep(10000);
			continue;
		}

		t2 = microtime();
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld", key, nextId);

		printf("%s#####################################################################%s\n", color_yellow, color_cls);
		printf("%s##### %s #####%s\n", color_red, keybuf, color_cls);
		printf("%s#####################################################################%s\n", color_yellow, color_cls);
		
	retry:
		if(!redis_send(&redis, "ss", "hgetall", keybuf)) goto end;
		if(!redis_recv(&redis, REDIS_FLAG_MULTI)) goto end;

		if(encoding) {
			free(encoding);
			encoding = NULL;
		}
		for(i = 0; i < redis.data.sz; i += 2) {
			if(!strcmp(redis.data.data[i].str, "contentEncoding") && redis.data.data[i+1].sz > 0) {
				encoding = strndup(redis.data.data[i+1].str, redis.data.data[i+1].sz);
			}
			printf("%s", color_green);
			fwrite(redis.data.data[i].str, 1, redis.data.data[i].sz, stdout);
			printf("(%d):%s\n", redis.data.data[i+1].sz, color_cls);
			fwrite(redis.data.data[i+1].str, 1, redis.data.data[i+1].sz, stdout);
			printf("\n");
		}

		if(redis.data.sz > 0) {
			if(!redis_del(&redis, keybuf, &exists)) goto end;
			fflush(stdout);
			fflush(stderr);
		}
		
		if(!redis_del(&redis, keybuf, &exists)) goto end;
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld:post", key, nextId);
		if(!redis_get_ex(&redis, keybuf, &str, &size)) goto end;
		if(size > 0) {
			printf("%spostText(%d):%s\n", color_green, size, color_cls);
			fwrite(str, 1, size, stdout);
			printf("\n");

			if(!redis_del(&redis, keybuf, &exists)) goto end;
			fflush(stdout);
			fflush(stderr);
		}
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld:response", key, nextId);
		if(!redis_get_ex(&redis, keybuf, &str, &size)) goto end;
		if(size > 0) {
			printf("%sresponseText(%d):%s\n", color_green, size, color_cls);
			char *out = NULL;
			size_t outlen = 0;
			if(!encoding) {
				fwrite(str, 1, size, stdout);
			} else if(!strcmp(encoding, "gzip")) {
				if(php_zlib_decode(str, size, &out, &outlen, PHP_ZLIB_ENCODING_GZIP, 0)) {
					fwrite(out, 1, outlen, stdout);
					free(out);
				}
			} else if(!strcmp(encoding, "deflate")) {
				if(php_zlib_decode(str, size, &out, &outlen, PHP_ZLIB_ENCODING_DEFLATE, 0)) {
					fwrite(out, 1, outlen, stdout);
					free(out);
				}
			} else {
				fwrite(str, 1, size, stdout);
			}
			printf("\n");

			if(!redis_del(&redis, keybuf, &exists)) goto end;
			fflush(stdout);
			fflush(stderr);
		}

		t3 = microtime();

		printf("%s=====================================================================%s\n", color_yellow, color_cls);
		printf("%sDump id:%s %ld\n%sWait time:%s %lf\n%sRun time:%s %lf\n", color_red, color_cls, nextId, color_red, color_cls, t2 - t, color_red, color_cls, t3 - t2);
		fflush(stdout);
		fflush(stderr);

		t = microtime();
	}
	
	if(str) {
		free(str);
	}

	if(!redis_quit(&redis)) goto end;

end:
	redis_close(&redis);
	redis_destory(&redis);

	if(encoding) free(encoding);

	return 0;

usage:
	fprintf(stderr,
		"Usage: %s [options] [--] [cmd [arg [arg ...]]] [\\; cmd2 [arg2 [arg2...]]] ... \n"
		"    options\n"
		"        -h <host>            Server hostname (value: %s)\n"
		"        -p <port>            Server port (value: %d)\n"
		"        -a <password>        Password to use when connecting to the server(value: %s)\n"
		"        -n <database>        Database number(value: %d)\n"
		"        -k <key>             store key prefix(value: %s)\n"
		"        -d                   Open network debug info\n"
		"        -v                   Output version and exit\n"
		"        -?                   Output this help and exit\n"
		, argv[0], host, port, auth, database, key);

	return status;
}
