package chapter4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * RSA example with random key generation.
 */
public class RandomKeyRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(256, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));
        
        // encryption step
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));
        
        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils.toHex(plainText));
    }
}
