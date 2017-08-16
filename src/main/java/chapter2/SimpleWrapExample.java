package chapter2;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class SimpleWrapExample
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
        
        Cipher cipher = Cipher.getInstance("AESWrap", "BC");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        
        Key wrapKey = keyGen.generateKey();
        
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        
        byte[] wrappedKey = cipher.wrap(keyToBeWrapped);

        System.out.println("wrapped  : " + Utils.toHex(wrappedKey));
        
        // unwrap the wrapped key
        
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        
        Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        System.out.println("unwrapped: " + Utils.toHex(key.getEncoded()));
    }
}
