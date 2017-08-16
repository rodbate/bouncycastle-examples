package chapter6;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V1CertificateGenerator;


/**
 * Basic X.509 V1 Certificate creation.
 */
public class X509V1CreateExample
{
    public static X509Certificate generateV1Certificate(KeyPair pair)
        throws InvalidKeyException, NoSuchProviderException, SignatureException
    {
        // generate the certificate
        X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        // create the keys
        KeyPair          pair = Utils.generateRSAKeyPair();
        
        // generate the certificate
        X509Certificate cert = generateV1Certificate(pair);

        // show some basic validation
        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());
        
        System.out.println("valid certificate generated");
    }
}
