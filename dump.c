#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <signal.h>

#include "redis.h"

volatile bool is_running = true;

void sig_handle(int sig) {
	is_running = false;
}

bool redis_lpop_int(redis_t *redis, const char *key, long int *value) {
	if(!redis_send(redis, "ss", "lpop", key)) return false;
	if(!redis_recv(redis, REDIS_FLAG_BULK)) return false;
	
	if(redis->data.sz > 0) *value = strtol(redis->data.str, NULL, 10);
	else *value = 0;

	return true;
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
	char *str;
	int size, exists;

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

	signal(SIGINT, sig_handle);
	signal(SIGTERM, sig_handle);

	while(is_running) {
		if(!redis_lpop_int(&redis, key, &nextId)) goto end;
		
		if(nextId <= 0) {
			usleep(10000);
			continue;
		}
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld", key, nextId);

		printf("\033[33m#######################################################\033[0m\n");
		printf("\033[31m##### %s #####\033[0m\n", keybuf);
		printf("\033[33m#######################################################\033[0m\n");
		
	retry:
		if(!redis_send(&redis, "ss", "hgetall", keybuf)) goto end;
		if(!redis_recv(&redis, REDIS_FLAG_MULTI)) goto end;

		for(i = 0; i < redis.data.sz; i += 2) {
			printf("\033[32m");
			fwrite(redis.data.data[i].str, 1, redis.data.data[i].sz, stdout);
			printf("(%d):\033[0m\n", redis.data.data[i+1].sz);
			fwrite(redis.data.data[i+1].str, 1, redis.data.data[i+1].sz, stdout);
			printf("\n");
		}
		
		if(!redis_del(&redis, keybuf, &exists)) goto end;
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld:post", key, nextId);
		if(!redis_get_ex(&redis, keybuf, &str, &size)) goto end;
		if(size > 0) {
			printf("\033[32mpostText(%d):\033[0m\n", size);
			fwrite(str, 1, size, stdout);
			printf("\n");
		}
		
		if(!redis_del(&redis, keybuf, &exists)) goto end;
		
		snprintf(keybuf, sizeof(keybuf), "%s:%ld:response", key, nextId);
		if(!redis_get_ex(&redis, keybuf, &str, &size)) goto end;
		if(size > 0) {
			printf("\033[32mresponseText(%d):\033[0m\n", size);
			fwrite(str, 1, size, stdout);
			printf("\n");
		}
		
		if(!redis_del(&redis, keybuf, &exists)) goto end;
	}

	if(!redis_quit(&redis)) goto end;

end:
	redis_close(&redis);
	redis_destory(&redis);

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
