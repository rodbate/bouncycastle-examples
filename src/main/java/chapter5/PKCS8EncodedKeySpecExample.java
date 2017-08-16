package chapter5;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;

import chapter4.Utils;

/**
 * Simple example showing use of PKCS8EncodedKeySpec
 */
public class PKCS8EncodedKeySpecExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(128, Utils.createFixedRandom());

        KeyPair             pair = generator.generateKeyPair();

        // dump private key
        ASN1InputStream	    aIn = new ASN1InputStream(pair.getPrivate().getEncoded());
        PrivateKeyInfo      info = PrivateKeyInfo.getInstance(aIn.readObject());
        
        System.out.println(ASN1Dump.dumpAsString(info));        
        System.out.println(ASN1Dump.dumpAsString(info.getPrivateKey()));
        
        // create from specification
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded());
        KeyFactory          keyFact = KeyFactory.getInstance("RSA", "BC");
        PrivateKey          privKey = keyFact.generatePrivate(pkcs8Spec);

        if (privKey.equals(pair.getPrivate()))
        {
            System.out.println("key recovery successful");
        }
        else
        {
            System.out.println("key recovery failed");
        }
    }
}