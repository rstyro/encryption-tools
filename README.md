# Quick start
## Maven 引入
```
<!-- https://mvnrepository.com/artifact/top.lrshuai.encryption/encryption-tools -->
<dependency>
    <groupId>top.lrshuai.encryption</groupId>
    <artifactId>encryption-tools</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 一个加密工具类
+ SHAUtil
    + jdkSHA1(String key)  
        jdk包实现的
    + bcSHA1(String key)
    + bcSHA224(String key)
    + bcSHA224Two(String key)
    + ccSHA1(String key)
    + ccSHA2(String key)
+ MDUtil
    + jdkMD5(String key)
    + jdkMD2(String key)
    + bcMD4(String key)
    + bcMD42(String key)
    + bcMD5(String key)
    + ccMD5(String key)
    + ccMD2(String key)
