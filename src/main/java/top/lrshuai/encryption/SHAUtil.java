package top.lrshuai.encryption;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;

/**
 * 
 * @author rstyro
 */
public class SHAUtil {
    public static String jdkSHA1(String key) throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(key.getBytes());
        return Hex.encodeHexString(md.digest());
    }


    public static String bcSHA1(String key) throws Exception{
        Digest digest = new SHA1Digest();
        digest.update(key.getBytes(), 0,key.getBytes().length);
        byte[] shabtyte = new byte[digest.getDigestSize()];
        digest.doFinal(shabtyte, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(shabtyte);
    }
    public static String bcSHA224(String key) throws Exception{
        Digest digest = new SHA224Digest();
        digest.update(key.getBytes(), 0,key.getBytes().length);
        byte[] shabtyte = new byte[digest.getDigestSize()];
        digest.doFinal(shabtyte, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(shabtyte);
    }

    public static String bcSHA224Two(String key) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("SHA-224");
        md.update(key.getBytes());
        return Hex.encodeHexString(md.digest());
    }


    public static String ccSHA1(String key) {
        return DigestUtils.sha1Hex(key.getBytes());
    }

    public static String ccSHA2(String key) {
        return DigestUtils.shaHex(key);
    }

    public static void main(String[] args) throws Exception {
        String key = "www.lrshuai.top";
        System.out.println(jdkSHA1(key));
        System.out.println(bcSHA1(key));
        System.out.println(bcSHA224(key));
        System.out.println(bcSHA224Two(key));
    }
}
