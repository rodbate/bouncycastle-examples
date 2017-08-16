package chapter5;

import java.security.*;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;

/**
 * Basic class for exploring a PKCS #1 V1.5 Signature.
 */
public class PKCS1SigEncodingExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        keyGen.initialize(512, new SecureRandom());
        
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("SHA256withRSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();
        
        // open the signature
        Cipher	cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        
        byte[]  decSig = cipher.doFinal(sigBytes);
        
        // parse the signature
        ASN1InputStream	aIn = new ASN1InputStream(decSig);
        ASN1Sequence	seq = (ASN1Sequence)aIn.readObject();
        
        System.out.println(ASN1Dump.dumpAsString(seq));
        
        // grab a digest of the correct type
        MessageDigest	hash = MessageDigest.getInstance("SHA-256", "BC");
        
        hash.update(message);

        ASN1OctetString	sigHash = (ASN1OctetString)seq.getObjectAt(1);
        if (MessageDigest.isEqual(hash.digest(), sigHash.getOctets()))
        {
            System.out.println("hash verification succeeded");
        }
        else
        {
            System.out.println("hash verification failed");
        }
    }
}