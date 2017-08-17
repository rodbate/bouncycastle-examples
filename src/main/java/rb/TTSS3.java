package rb;

import chapter2.Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 *
 * Created by rodbate on 2017/8/17.
 */
public class TTSS3 extends BaseClass {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] input = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

    private static byte[] keyBytes = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    private static byte[] ivBytes = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};


    private static void invoke1() throws Exception {
        System.out.println("input : " + Utils.toHex(input) + "  bytes : " + input.length);

        Cipher c = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");


        //encryption
        c.init(Cipher.ENCRYPT_MODE, keySpec);
        IvParameterSpec parameterSpec = new IvParameterSpec(c.getIV());
        byte[] cipherText = c.doFinal(input);
        System.out.println("cipher : " + Utils.toHex(cipherText) + "  bytes : " + cipherText.length);


        //decryption
        c.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);
        byte[] plainText = c.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText) + "  bytes : " + plainText.length);
    }


    private static void invoke2() throws Exception {
        System.out.println("input : " + Utils.toHex(input) + "  bytes : " + input.length);

        Cipher c = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        //IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);
        byte[] iv = new byte[8];
        RANDOM.nextBytes(iv);
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);

        //encrypt
        c.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);
        byte[] cipherText = c.doFinal(input);
        System.out.println("cipher : " + Utils.toHex(cipherText) + "  bytes : " + cipherText.length);

        //decryption
        c.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);
        byte[] plainText = c.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText) + "  bytes : " + plainText.length);
    }


    private static void invoke3() throws Exception {
        System.out.println("input : " + Utils.toHex(input) + "  bytes : " + input.length);

        Cipher c = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES", "BC");
        keyGenerator.init(64);
        SecretKey secretKey = keyGenerator.generateKey();

        //encrypt
        c.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = c.doFinal(input);
        System.out.println("cipher : " + Utils.toHex(cipherText) + "  bytes : " + cipherText.length);

        //decryption
        c.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        byte[] plainText = c.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText) + "  bytes : " + plainText.length);
    }



    public static void main(String[] args) throws Exception {
        //invoke1();
        //invoke2();
        invoke3();
    }
}
