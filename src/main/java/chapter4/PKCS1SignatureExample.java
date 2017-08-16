package chapter4;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Generating a PKCS1 v1.5 style signature.
 */
public class PKCS1SignatureExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        keyGen.initialize(512, new SecureRandom());
        
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("SHA1withRSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();
        
        // verify a signature
        signature.initVerify(keyPair.getPublic());

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }
}
