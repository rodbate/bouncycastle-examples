package chapter4;

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import rb.BaseClass;

import java.io.PrintWriter;
import java.security.*;

import javax.crypto.Cipher;

/**
 * RSA example with PKCS1 Padding.
 */
public class PKCS1PaddedRSAExample extends BaseClass {
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(256, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(System.out));
        writer.writeObject(pubKey);
        writer.writeObject(privKey);
        writer.close();


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
