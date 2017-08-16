package chapter4;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Simple example showing signature creation and verification using ECDSA
 */
public class BasicECDSAExample
{
    public static void main(
        String[]    args)
    	throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        
        keyGen.initialize(ecSpec, new SecureRandom());
        
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("ECDSA", "BC");

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