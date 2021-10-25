# mod_dump_redis
The request detail data is captured and stored in redis based on the Apache module

### 1. DumpRedisHost
DumpRedisHost <ipaddr>

* ipaddr: IP address of redis (type: String)

### 2. DumpRedisPort
DumpRedisPort <port>

* port: Redis port (type: integer)

### 3. DumpRedisAuth
DumpRedisAuth <password>

* password: Redis security password (type: String)

### 4. DumpRedisDatabase
DumpRedisDatabase <database>

* database: Redis database (type: integer)

### 5. DumpRedisKey
DumpRedisKey <key>

* key: Key prefix stored in redis

### 6. DumpRedisEnable
DumpRedisEnable <On|Off>

* On: enable redis dump
* Off: disable redis dump

### 7. DumpRedisRule
DumpRedisRule <regex>...

* regex: regular expression

