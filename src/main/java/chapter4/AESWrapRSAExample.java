package chapter4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Wrapping an RSA Key using AES
 */
public class AESWrapRSAExample
{
    public static void main(
        String[]    args)
		throws Exception
    {
        Cipher       cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecureRandom random = new SecureRandom();
        
        KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
        fact.initialize(1024, new SecureRandom());

        KeyPair     keyPair = fact.generateKeyPair();
        Key         wrapKey = Utils.createKeyForAES(256, random);
        
        // wrap the RSA private key
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        
        byte[] wrappedKey = cipher.wrap(keyPair.getPrivate());

        // unwrap the RSA private key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        
        Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);

        if (keyPair.getPrivate().equals(key))
        {
            System.out.println("Key recovered.");
        }
		else
		{
		    System.out.println("Key recovery failed.");
		}
    }
}
