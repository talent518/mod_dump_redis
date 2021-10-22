#!/usr/bin/sh

lampp stopapache

rm -rf .libs *.o *.slo *.lo *.la

apxs -cia -l m -n dump_redis mod_dump_redis.c redis.c

chown daemon.daemon /opt/lampp/modules/mod_dump_redis.so

lampp startapache

gcc -o redis-dump -lm dump.c redis.c

