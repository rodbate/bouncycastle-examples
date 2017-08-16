package chapter2;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class SimpleCipherWrapExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        // create a key to wrap
        
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(128);

        Key	keyToBeWrapped = generator.generateKey();

        System.out.println("input    : " + Utils.toHex(keyToBeWrapped.getEncoded()));
        
        // create a wrapper and do the wrapping
        
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        
        Key wrapKey = keyGen.generateKey();
        
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey);
        
        byte[] wrappedKey = cipher.doFinal(keyToBeWrapped.getEncoded());

        System.out.println("wrapped  : " + Utils.toHex(wrappedKey));
        
        // unwrap the wrapped key
        
        cipher.init(Cipher.DECRYPT_MODE, wrapKey);
        
        Key key = new SecretKeySpec(cipher.doFinal(wrappedKey), "AES");

        System.out.println("unwrapped: " + Utils.toHex(key.getEncoded()));
    }
}
