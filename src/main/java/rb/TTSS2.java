package rb;

import chapter2.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * Created by rodbate on 2017/8/17.
 */
public class TTSS2 extends BaseClass {

    public static void main(String[] args) throws Exception {

        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

        byte[] keyBytes = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };


        Cipher c = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        System.out.println("input : " + Utils.toHex(input) + "  bytes : " + input.length);


        //encryption
        c.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] cipherText = c.doFinal(input);
        System.out.println("cipher : " + Utils.toHex(cipherText) + "  bytes : " + cipherText.length);


        //decryption 1
        c.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] plainText = c.doFinal(cipherText);
        System.out.println("plain 1 : " + Utils.toHex(plainText) + "  bytes : " + plainText.length);

        //decryption 2
        c.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] plainText2 = new byte[c.getOutputSize(cipherText.length)];
        int pLen = c.doFinal(cipherText, 0, cipherText.length, plainText2, 0);
        System.out.println("plain 2 : " + Utils.toHex(plainText2, pLen) + "  bytes : " + pLen);
    }
}
