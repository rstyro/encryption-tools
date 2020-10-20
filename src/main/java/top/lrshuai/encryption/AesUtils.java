package top.lrshuai.encryption;


import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.UUID;

/**
 * aes对称加密工具类
 *
 * @author rstyro
 */
public class AesUtils {

    /**
     * 算法
     */
    public static final String AES = "AES";

    /**
     * 算法:AES/加密模式:ECB/填充方式:PKCS5Padding
     * 默认:AES/ECB/PKCS5Padding
     * ECB模式不支持向量
     */
    public static final String CIPHER_MODE_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";
    public static final String CIPHER_MODE_ECB_PKCS7PADDING = "AES/ECB/PKCS7Padding";
    public static final String CIPHER_MODE_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";

    /**
     * 编码
     */
    public static final String CHARSET_NAME = "UTF-8";

    /**
     * 生成密钥的长度
     */
    public static final int KEY_SIZE_128 = 128;
    public static final int KEY_SIZE_192 = 192;
    public static final int KEY_SIZE_256 = 256;

    /**
     * 这个不能在代码里面new 可参数：https://www.bbsmax.com/A/lk5aQo7451/ 解释
     * javax.crypto.JceSecurity.getVerificationResult()
     */
    private static final BouncyCastleProvider BOUNCYCASTLEPROVIDER = new BouncyCastleProvider();


    /**
     * 生成随机密钥
     * @param keySize 密钥大小: 128 192 256
     * 128 返回16位key
     * 192 返回24位key
     * 256 返回32位key
     * @return 返回随机密钥
     */
    public static String generateSecret(int keySize) {
        String result = UUID.randomUUID().toString().replaceAll("-", "");
        if(KEY_SIZE_128 == keySize){
            result = result.substring(0,16);
        }else if(KEY_SIZE_192 == keySize){
            result = result.substring(0,24);
        }else if(KEY_SIZE_256 == keySize){
            result = result.substring(0,32);
        }else {
            throw new RuntimeException("参数错误，长度可选：128、192、256");
        }
        return result;
    }

    /**
     * 加密
     * @param content 需要加密的字符串
     * @param pwdKey 密钥
     * @return 返回加密后的字节数组
     * @throws GeneralSecurityException error
     * @throws UnsupportedEncodingException err
     */
    public static byte[] encrypt(String content, String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE,pwdKey,null,CIPHER_MODE_ECB_PKCS5PADDING);
        return cipher.doFinal(content.getBytes(CHARSET_NAME));
    }

    /**
     * 加密
     * @param content 需要加密的字符串
     * @param pwdKey 密钥
     * @param iv 向量
     * @param transformMode 加密模式
     * @return 返回加密后的字节数组
     * @throws GeneralSecurityException error
     * @throws UnsupportedEncodingException err
     */
    public static byte[] encryptByIv(String content, String pwdKey,byte[] iv,String transformMode) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE,pwdKey,iv,transformMode);
        return cipher.doFinal(content.getBytes(CHARSET_NAME));
    }

    /**
     * base64 加密后aes加密
     * @param content 内容
     * @param pwdKey 密钥
     * @return 返回加密后的字符串
     * @throws GeneralSecurityException err
     * @throws UnsupportedEncodingException err
     */
    public static String encodeBase64(String content,String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        return Base64.encodeBase64String(encrypt(content,pwdKey));
    }

    /**
     * base64 加密后aes加密
     * @param content 内容
     * @param pwdKey 密钥
     * @param iv 向量
     * @param transformMode 加密模式
     * @return 返回加密后的字符串
     * @throws GeneralSecurityException err
     * @throws UnsupportedEncodingException err
     */
    public static String encodeBase64(String content,String pwdKey,byte[] iv,String transformMode) throws GeneralSecurityException, UnsupportedEncodingException {
        return Base64.encodeBase64String(encryptByIv(content,pwdKey,iv,transformMode));
    }

    /**
     * 解密
     * @param content 需要解密的字符串
     * @param pwdKey 密钥
     * @return 返回解密后的字节数组
     */
    public static byte[] decrypt(byte[] content, String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE,pwdKey,null,CIPHER_MODE_ECB_PKCS5PADDING);
        return cipher.doFinal(content);
    }

    /**
     * 解密
     * @param content 需要解密的字符串
     * @param pwdKey 密钥
     * @param iv 向量
     * @param transformMode 加密模式
     * @return 返回解密后的字节数组
     */
    public static byte[] decryptByIv(byte[] content, String pwdKey,byte[] iv,String transformMode) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE,pwdKey,iv,transformMode);
        return cipher.doFinal(content);
    }

    /**
     * base64解密后aes解密
     * @param content 内容
     * @param pwdKey 密钥
     * @return 返回解密后的明文字符串
     * @throws GeneralSecurityException error
     * @throws UnsupportedEncodingException err
     */
    public static String decodeBase64(String content,String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        return new String(decrypt(Base64.decodeBase64(content),pwdKey),CHARSET_NAME);
    }

    /**
     * base64解密后aes解密
     * @param content 内容
     * @param pwdKey 密钥
     * @param iv 向量
     * @param transformMode 加密模式
     * @return 返回解密后的明文字符串
     * @throws GeneralSecurityException error
     * @throws UnsupportedEncodingException err
     */
    public static String decodeBase64(String content,String pwdKey,byte[] iv,String transformMode) throws GeneralSecurityException, UnsupportedEncodingException {
        return new String(decryptByIv(Base64.decodeBase64(content),pwdKey,iv,transformMode),CHARSET_NAME);
    }

    /**
     * 获取 cipher
     * @param cipherMode 模式
     * @param pwdKey 密钥
     * @param iv 向量
     * @param transformMode 加密模式
     * @return 返回cipher
     * @throws GeneralSecurityException error
     * @throws UnsupportedEncodingException error
     */
    private static Cipher getCipher(int cipherMode, String pwdKey,byte[] iv,String transformMode) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] raw = pwdKey.getBytes(CHARSET_NAME);
        // 这个地方主要是兼容 PKCS7Padding
        Security.addProvider(BOUNCYCASTLEPROVIDER);
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES);
        Cipher cipher = Cipher.getInstance(transformMode);
        if(iv != null && iv.length>0){
            cipher.init(cipherMode, secretKeySpec,new IvParameterSpec(iv));
        }else{
            cipher.init(cipherMode, secretKeySpec);
        }
        return cipher;
    }


    public static void main(String[] args) throws Exception {
        String pwd = generateSecret(KEY_SIZE_192);
        System.out.println("pwd="+pwd);
        System.out.println("pwd="+pwd.length());
        String text =  "abcAAA";
        String encode = encodeBase64(text,pwd,"1234567890123456".getBytes(),CIPHER_MODE_CBC_PKCS5PADDING);
        System.out.println("encode1="+encode);
        String decrypt2 =decodeBase64(encode,pwd,"1234567890123456".getBytes(),CIPHER_MODE_CBC_PKCS5PADDING);
        System.out.println("decrypt2="+decrypt2);

        String encode3 = encodeBase64(text,pwd,null,CIPHER_MODE_ECB_PKCS7PADDING);
        System.out.println("encode3="+encode3);
        String decrypt4 =decodeBase64(encode3,pwd,null,CIPHER_MODE_ECB_PKCS7PADDING);
        System.out.println("decrypt4="+decrypt4);

        String encode5 = encodeBase64(text,pwd);
        System.out.println("encode5="+encode5);
        String decrypt6 =decodeBase64(encode5,pwd);
        System.out.println("decrypt6="+decrypt6);

    }
}
