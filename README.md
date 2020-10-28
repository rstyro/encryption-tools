# Quick start
## Maven 引入
```
<!-- https://mvnrepository.com/artifact/top.lrshuai.encryption/encryption-tools -->
<dependency>
    <groupId>top.lrshuai.encryption</groupId>
    <artifactId>encryption-tools</artifactId>
    <version>1.0.4</version>
</dependency>
```

## Gradle 引入
```
// https://mvnrepository.com/artifact/top.lrshuai.encryption/encryption-tools
compile group: 'top.lrshuai.encryption', name: 'encryption-tools', version: '1.0.4'
```

### 一个加密工具类
+ SHAUtil
    + SHA加密，有SHA1、SHA224,代码调用
```
public static void main(String[] args) throws Exception {
    String key = "www.lrshuai.top";
    System.out.println(jdkSHA1(key));
    System.out.println(bcSHA1(key));
    System.out.println(bcSHA224(key));
    System.out.println(bcSHA224Two(key));
}
``` 
+ MDUtil
    + MD加密，有：MD5、MD4、MD2加密，有不同的实现：jdk、bc、cc，使用如下：
```
public static void main(String[] args) throws Exception {
    String key = "www.lrshuai.top";
    System.out.println(jdkMD5(key));
    System.out.println(jdkMD2(key));
    System.out.println(bcMD4(key));
    System.out.println(bcMD42(key));
    System.out.println(bcMD5(key));
    System.out.println(ccMD5(key));
    System.out.println(ccMD2(key));
}
```
+ RsaUtil
    + rsa加解密工具，包含生成公私钥，签名验证、加解密，使用如下：
```
    public static void main(String[] args) throws Exception {
        Map<String, String> keyMap = genKeyPair();
        String myPublicKey = keyMap.get(RsaUtil.PUBLIC_KEY);
        String myPrivateKey = keyMap.get(RsaUtil.PRIVATE_KEY);

        String text = "我是需要加密的文本abc";
        String encodePublicKey = RsaUtils.encodeBase64PublicKey(myPublicKey, text);
        String encodePrivateKey = RsaUtils.encodeBase64PrivateKey(myPrivateKey, text);
        System.out.println("公钥加密=" + encodePublicKey);
        System.out.println("私钥加密=" + encodePrivateKey);
        // 私钥加密公钥解密
        String decodeByPublicKey = RsaUtils.decodeBase64ByPublicKey(myPublicKey, encodePrivateKey);
        // 公钥加密私钥解密
        String decodeByPrivate = RsaUtils.decodeBase64ByPrivate(myPrivateKey, encodePublicKey);
        System.out.println();
        System.out.println("私钥解密=" + decodeByPrivate);
        System.out.println("公钥解密=" + decodeByPublicKey);
        String sign = RsaUtils.sign(RsaUtils.SIGNATURE_SHA1_ALGORITHM, myPrivateKey, text.getBytes());
        System.out.println("sign=" + sign);
        boolean verify = RsaUtils.verify(RsaUtils.SIGNATURE_SHA1_ALGORITHM, myPublicKey, text.getBytes(), sign);
        System.out.println("is verify=" + verify);
    }
```
+ AesUtil
    + aes加解密方法，支持:`ECB`、`CBC`、`CTR`、`OFB`、`CFB` 5种加密模式,`PKCS5Padding`与`PKCS7Padding`的填充方式。
```
public static void main(String[] args) throws Exception {
    // 生成密钥
    String pwd = generateSecret(AesUtil.KEY_SIZE_256);
    System.out.println("pwd="+pwd);
    System.out.println("pwd="+pwd.length());
    String text =  "abcAAA";
    // 加密
    String encode5 = encodeBase64(text,pwd);
    System.out.println("encode5="+encode5);
    // 解密
    String decrypt6 =decodeBase64(encode5,pwd);
    System.out.println("decrypt6="+decrypt6);
    // 向量
    byte[] iv = "1234567890123456".getBytes();
    // 有向量的加密
    String encode7 = encodeBase64(text,pwd,iv,AesUtil.CIPHER_MODE_OFB_PKCS5PADDING);
    System.out.println("encode3="+encode7);
    // 有向量的解密
    String decrypt8 =decodeBase64(encode7,pwd,iv,AesUtil.CIPHER_MODE_OFB_PKCS5PADDING);
    System.out.println("decrypt4="+decrypt8);
}
```
