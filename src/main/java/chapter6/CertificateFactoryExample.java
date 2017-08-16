package chapter6;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Basic example of using a CertificateFactory.
 */
public class CertificateFactoryExample
{
    public static void main(String[] args)
        throws Exception
    {
        // create the keys
        KeyPair          pair = Utils.generateRSAKeyPair();
        
        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        bOut.write(X509V1CreateExample.generateV1Certificate(pair).getEncoded());
        
        bOut.close();
        
        InputStream in = new ByteArrayInputStream(bOut.toByteArray());
        
        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        
        // read the certificate
        X509Certificate    x509Cert = (X509Certificate)fact.generateCertificate(in);
        
        System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
    }
}
