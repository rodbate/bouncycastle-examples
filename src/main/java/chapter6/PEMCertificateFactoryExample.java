package chapter6;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMWriter;

/**
 * Basic example of using a CertificateFactory.
 */
public class PEMCertificateFactoryExample
{
    public static void main(String[] args)
        throws Exception
    {
        // create the keys
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        kpGen.initialize(1024, new SecureRandom());
        
        KeyPair          pair = kpGen.generateKeyPair();
        
        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        PEMWriter             pemWrt = new PEMWriter(new OutputStreamWriter(bOut));
        
        pemWrt.writeObject(X509V1CreateExample.generateV1Certificate(pair));
        
        pemWrt.close();
        
        bOut.close();
        
        System.out.println(Utils.toString(bOut.toByteArray()));
        
        InputStream in = new ByteArrayInputStream(bOut.toByteArray());
        
        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        
        // read the certificate
        X509Certificate    x509Cert = (X509Certificate)fact.generateCertificate(in);
        
        System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
    }
}
