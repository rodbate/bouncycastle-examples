package chapter1;

import javax.crypto.Cipher;

/**
 * Basic demonstration of precedence in action.
 */
public class PrecedenceTest
{
    public static void main(
        String[]    args)
        throws Exception
    {
        Cipher        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        
        System.out.println(cipher.getProvider());
        
        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        
        System.out.println(cipher.getProvider());
    }
}
