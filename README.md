# mod_dump_redis
基于apache模块实现的请求详情数据的抓取并存储到redis

### 1. DumpRedisHost
DumpRedisHost <ipaddr>

* database: redis的IP地址（类型：字符串）

### 2. DumpRedisPort
DumpRedisPort <port>

* database: redis的端口（类型：整数）

### 3. DumpRedisAuth
DumpRedisAuth <password>

* database: redis的安全密码（类型：字符串）

### 4. DumpRedisDatabase
DumpRedisDatabase <database>

* database: redis的数据库（类型：整数）

### 5. DumpRedisKey
DumpRedisKey <key>

* key: 存储于redis中的key前缀

### 6. DumpRedisEnable
DumpRedisEnable <On|Off>

* On: 启用
* Off: 禁用

### 7. DumpRedisRule
DumpRedisRule <regex>...

* regex: 正则表达式

