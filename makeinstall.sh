#!/usr/bin/sh

rm -rf .libs *.o *.slo *.lo *.la

apxs -cia -l m -n dump_redis mod_dump_redis.c redis.c

gcc -O2 -g -o redis-dump -lm dump.c redis.c -lz

