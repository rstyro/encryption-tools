package top.lrshuai.encryption;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.Security;

public class MDUtil {
    public static String jdkMD5(String key) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] mdbyte = md.digest(key.getBytes());
        return Hex.encodeHexString(mdbyte);
    }
    public static String jdkMD2(String key) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD2");
        byte[] mdbyte = md.digest(key.getBytes());
        return Hex.encodeHexString(mdbyte);
    }

    public static String bcMD4(String key) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("MD4");
        byte[] mdbyte = md.digest(key.getBytes());
        return Hex.encodeHexString(mdbyte);
    }

    public static String bcMD42(String key) throws Exception{
        Digest digest = new MD4Digest();
        digest.update(key.getBytes(), 0,key.getBytes().length);
        byte[] bcbtyte = new byte[digest.getDigestSize()];
        digest.doFinal(bcbtyte, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bcbtyte);
    }

    public static String bcMD5(String key) throws Exception{
        Digest digest = new MD5Digest();
        digest.update(key.getBytes(), 0,key.getBytes().length);
        byte[] bcbtyte = new byte[digest.getDigestSize()];
        digest.doFinal(bcbtyte, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bcbtyte);
    }

    public static String ccMD5(String key) {
        return DigestUtils.md5Hex(key.getBytes());
    }

    public static String ccMD2(String key) {
        return DigestUtils.md2Hex(key.getBytes());
    }

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
}