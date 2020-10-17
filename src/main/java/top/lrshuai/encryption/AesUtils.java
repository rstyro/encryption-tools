package top.lrshuai.encryption;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
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
    private static final String AES = "AES";

    /**
     * 算法:AES/加密模式:ECB/填充方式:PKCS5Padding
     */
    private static final String AES_PKCS5P = "AES/ECB/PKCS5Padding";

    /**
     * 编码
     */
    private static final String CHARSET_NAME = "UTF-8";

    private static final int KEY_SIZE_128 = 128;
    private static final int KEY_SIZE_192 = 192;
    private static final int KEY_SIZE_256 = 256;


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
     */
    public static byte[] encrypt(String content, String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE,pwdKey);
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
     * 解密
     * @param content 需要解密的字符串
     * @param pwdKey 密钥
     * @return 返回解密后的字节数组
     */
    public static byte[] decrypt(byte[] content, String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE,pwdKey);
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

    private static Cipher getCipher(int cipherMode, String pwdKey) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] raw = pwdKey.getBytes(CHARSET_NAME);
        SecretKeySpec secretKeySpec = new SecretKeySpec(raw, AES);
        Cipher cipher = Cipher.getInstance(AES_PKCS5P);
        cipher.init(cipherMode, secretKeySpec);
        return cipher;
    }


    public static void main(String[] args) throws Exception {
        String pwd = generateSecret(KEY_SIZE_256);
        System.out.println("pwd="+pwd);
        System.out.println("pwd="+pwd.length());
        String text =  "abcAAA";
        byte[] bytes = "我是谁".getBytes();
        System.out.println(new String(bytes,CHARSET_NAME));
        String encode = encodeBase64(text,pwd);
        System.out.println("encode="+encode);
        String decrypt2 =decodeBase64(encode,pwd);
        System.out.println("decrypt="+decrypt2);

    }
}
