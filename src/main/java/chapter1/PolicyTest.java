package chapter1;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class that does some basic cryptographic operations to confirm what
 * policy restrictions exist in the Java runtime it is running in.
 */
public class PolicyTest
{
    public static void main(
        String[]  args)
    {
        byte[]           data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

        SecretKeySpec    key64 = new SecretKeySpec(
                            new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
                            "Blowfish");
        
        try
        {
            Cipher       c = Cipher.getInstance("Blowfish/ECB/NoPadding");
        
            c.init(Cipher.ENCRYPT_MODE, key64);
        
            c.doFinal(data);
            
            System.out.println("64 bit test: passed");
        }
        catch (SecurityException e)
        {
            if (e.getMessage() == "Unsupported keysize or algorithm parameters")
            {
                System.out.println("64 bit test failed: unrestricted policy files have not been installed for this runtime.");
            }
            else
            {
                System.err.println("64 bit test failed: there are bigger problems than just policy files: " + e);
            }
        }
        catch (GeneralSecurityException e)
        {
            System.err.println("64 bit test failed: there are bigger problems than just policy files: " + e);
        }
        
        SecretKeySpec    key192 = new SecretKeySpec(
                            new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
                            "Blowfish");
        
        try
        {
            Cipher       c = Cipher.getInstance("Blowfish/ECB/NoPadding");
        
            c.init(Cipher.ENCRYPT_MODE, key192);
        
            c.doFinal(data);
            
            System.out.println("192 bit test: passed");
        }
        catch (SecurityException e)
        {
            if (e.getMessage() == "Unsupported keysize or algorithm parameters")
            {
                System.out.println("192 bit test failed: unrestricted policy files have not been installed for this runtime.");
            }
            else
            {
                System.err.println("192 bit test failed: there are bigger problems than just policy files: " + e);
            }
        }
        catch (GeneralSecurityException e)
        {
            System.err.println("192 bit test failed: there are bigger problems than just policy files: " + e);
        }

        System.out.println("Tests completed");
    }
}
