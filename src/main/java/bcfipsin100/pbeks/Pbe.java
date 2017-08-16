package bcfipsin100.pbeks;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import bcfipsin100.base.Setup;
import org.bouncycastle.util.encoders.Hex;

public class Pbe
{
    public static SecretKey makePbeKey(char[] password)
        throws GeneralSecurityException
    {
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("HmacSHA384", "BCFIPS");

        SecretKey hmacKey = keyFact.generateSecret(new PBEKeySpec(password,  Hex.decode("0102030405060708090a0b0c0d0e0f10"), 1024, 256));

        return new SecretKeySpec(hmacKey.getEncoded(), "AES");
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Setup.installProvider();

        System.err.println("PBE Key: " + Hex.toHexString(makePbeKey("Hello World!".toCharArray()).getEncoded()));
    }
}
