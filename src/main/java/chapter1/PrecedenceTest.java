package chapter1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.Security;

/**
 * Basic demonstration of precedence in action.
 */
public class PrecedenceTest
{
    public static void main(
        String[]    args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Cipher        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        
        System.out.println(cipher.getProvider());
        
        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        
        System.out.println(cipher.getProvider());
    }
}
