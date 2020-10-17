package top.lrshuai.encryption;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA 公私钥加解密工具类
 * RSA MD5、SHA1 签名校验
 * 由于非对称加密速度极其缓慢，一般文件不使用它来加密而是使用对称加密
 * 非对称加密算法可以用来对对称加密的密钥加密，这样保证密钥的安全也就保证了数据的安全
 *
 * RSA 加解密的逻辑是这样的：
 * 公钥加密私钥解密，私钥解密公钥解密
 *
 * @author rstyro
 * @since 2020-10
 */
public class RsaUtils {
    /**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * MD5签名算法
     */
    public static final String SIGNATURE_MD5_ALGORITHM = "MD5withRSA";
    /**
     * SHA1 签名算法
     */
    public static final String SIGNATURE_SHA1_ALGORITHM = "SHA1withRSA";

    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    private static final String CHARSET_NAME = "UTF-8";

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * RSA 位数 如果采用2048 上面最大加密和最大解密则须填写:  245 256
     * RSA 位数于原文长度对应 以及越长速度越慢
     */
    private static final int INITIALIZE_LENGTH = 1024;

    /**
     * 生成密钥对(公钥和私钥)
     * @return 返回公私钥字符串
     * @throws Exception err
     */
    public static Map<String, String> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(INITIALIZE_LENGTH);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, String> keyMap = new HashMap<>(2);
        keyMap.put(PUBLIC_KEY, Base64.encodeBase64String(publicKey.getEncoded()));
        keyMap.put(PRIVATE_KEY, Base64.encodeBase64String(privateKey.getEncoded()));
        return keyMap;
    }

    /**
     * 用私钥对信息生成数字签名
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return 返回签名字符串
     * @throws Exception err
     */
    public static String sign(String signAlgorithm, String privateKey, byte[] data) throws Exception {
        PrivateKey privateK = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }

    /**
     * 公钥校验数字签名
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return 返回验签是否成功
     * @throws Exception err
     */
    public static boolean verify(String signAlgorithm, String publicKey, byte[] data, String sign) throws Exception {
        PublicKey publicK = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }

    /**
     * 私钥解密
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @return 返回解密内容byte数组
     * @throws Exception err
     */
    public static byte[] decryptByPrivateKey(String privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return segmentBytes(cipher, encryptedData, MAX_DECRYPT_BLOCK);
    }

    /**
     * 公钥解密
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @return 返回解密内容byte数组
     * @throws Exception err
     */
    public static byte[] decryptByPublicKey(String publicKey, byte[] encryptedData) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, getPublicKey(publicKey));
        return segmentBytes(cipher, encryptedData, MAX_DECRYPT_BLOCK);
    }

    /**
     * 公钥加密
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @return 返回的数据需要私钥才能解密
     * @throws Exception err
     */
    public static byte[] encryptByPublicKey(String publicKey, byte[] data) throws Exception {
        // 对数据加密
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return segmentBytes(cipher, data, MAX_ENCRYPT_BLOCK);
    }

    /**
     * 私钥加密
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @return 返回的数据需要公钥才能解密
     * @throws Exception err
     */
    public static byte[] encryptByPrivateKey(String privateKey, byte[] data) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, getPrivateKey(privateKey));
        return segmentBytes(cipher, data, MAX_ENCRYPT_BLOCK);
    }

    /**
     * 分段加解密
     * @param cipher   密码
     * @param data     数据
     * @param maxBlock 加密或解密的最大长度
     * @return byte[]
     */
    private static byte[] segmentBytes(Cipher cipher, byte[] data, int maxBlock) {
        byte[] result = null;
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int len = data.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (len - offSet > 0) {
                if (len - offSet > maxBlock) {
                    cache = cipher.doFinal(data, offSet, maxBlock);
                } else {
                    cache = cipher.doFinal(data, offSet, len - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * maxBlock;
            }
            result = out.toByteArray();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private static Cipher getCipher(int mode, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(mode, key);
        return cipher;
    }

    public static PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return keyFactory.generatePrivate(pkcs8KeySpec);
    }

    public static PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return keyFactory.generatePublic(x509KeySpec);
    }


    /**
     * 公钥加密后在base64编码
     * @param publicKey 公钥
     * @param data 需要加密的明文字符串
     * @return 加密后的字符串
     * @throws Exception err
     */
    public static String encodeBase64PublicKey(String publicKey, String data) throws Exception {
        return Base64.encodeBase64String(encryptByPublicKey(publicKey, data.getBytes()));
    }
    /**
     * 私钥加密后base64编码
     * @param privateKey 私钥
     * @param data 需要加密的明文字符串
     * @return 加密后的字符串
     * @throws Exception err
     */
    public static String encodeBase64PrivateKey(String privateKey, String data) throws Exception {
        return Base64.encodeBase64String(encryptByPrivateKey(privateKey, data.getBytes()));
    }

    /**
     * 私钥base64解码后再rsa解码
     * @param privateKey 私钥
     * @param data 公钥加密的数据
     * @return 返回明文
     * @throws Exception err
     */
    public static String decodeBase64ByPrivate(String privateKey, String data) throws Exception {
        return new String(decryptByPrivateKey(privateKey, Base64.decodeBase64(data)), CHARSET_NAME);
    }

    /**
     * 公钥钥base64解码后再rsa解码
     * @param publicKey 公钥
     * @param data 私钥加密的数据
     * @return 明文
     * @throws Exception err
     */
    public static String decodeBase64ByPublicKey(String publicKey, String data) throws Exception {
        return new String(decryptByPublicKey(publicKey, Base64.decodeBase64(data)), CHARSET_NAME);
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> keyMap = genKeyPair();
        String myPublicKey = keyMap.get(PUBLIC_KEY);
        String myPrivateKey = keyMap.get(PRIVATE_KEY);

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
//

    }
}
