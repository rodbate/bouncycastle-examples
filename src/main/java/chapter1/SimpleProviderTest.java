package chapter1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Basic class to confirm the Bouncy Castle provider is 
 * installed.
 */
public class SimpleProviderTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        String providerName = "BC";

        Provider provider;
        if ((provider = Security.getProvider(providerName)) == null)
        {
            System.out.println(providerName + " provider not installed");
        }
        else
        {
            System.out.println(provider);
            System.out.println(providerName + " is installed.");
        }
    }
}
