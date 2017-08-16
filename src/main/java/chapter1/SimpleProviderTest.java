package chapter1;

import java.security.Security;

/**
 * Basic class to confirm the Bouncy Castle provider is 
 * installed.
 */
public class SimpleProviderTest
{
    public static void main(String[] args)
    {
        String providerName = "BC";
        
        if (Security.getProvider(providerName) == null)
        {
            System.out.println(providerName + " provider not installed");
        }
        else
        {
            System.out.println(providerName + " is installed.");
        }
    }
}
