package chapter7;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.extension.*;

/**
 * Chapter 7 Utils
 */
public class Utils extends chapter6.Utils
{
    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
    
    /**
     * Generate a sample V1 certificate to use as a CA root certificate
     */
    /*public static X509Certificate generateRootCert(KeyPair pair)
        throws Exception
	{
	    X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();
	
	    certGen.setSerialNumber(BigInteger.valueOf(1));
	    certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
	    certGen.setNotBefore(new Date(System.currentTimeMillis()));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
	    certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
	    certGen.setPublicKey(pair.getPublic());
	    certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
	
	    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}
    
    *//**
     * Generate a sample V3 certificate to use as an intermediate CA certificate
     *//*
    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=Test Intermediate Certificate"));
        certGen.setPublicKey(intKey);
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
    
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(intKey));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return certGen.generateX509Certificate(caKey, "BC");
    }
    
    *//**
     * Generate a sample V3 certificate to use as an end entity certificate
     *//*
    public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
	    throws Exception
	{
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=Test End Certificate"));
        certGen.setPublicKey(entityKey);
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
        
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(entityKey));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        return certGen.generateX509Certificate(caKey, "BC");
	}*/
}