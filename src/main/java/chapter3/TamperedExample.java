package chapter3;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Tampered message, plain encryption, AES in CTR mode
 */
public class TamperedExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        SecureRandom	random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          input = "Transfer 0000100 to AC 1234-5678";

        System.out.println("input : " + input);
        
        // encryption step
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        byte[] cipherText = cipher.doFinal(Utils.toByteArray(input));

        // tampering step
        
        cipherText[9] ^= '0' ^ '9';
        
        // decryption step
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils.toString(plainText));
    }
}
