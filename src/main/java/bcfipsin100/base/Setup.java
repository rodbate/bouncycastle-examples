package bcfipsin100.base;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.Security;


public class Setup
{
    public static void installProvider()
    {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static void main(String[] args) {
        installProvider();
    }
}
