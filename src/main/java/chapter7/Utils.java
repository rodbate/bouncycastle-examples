package chapter7;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
    public static X509Certificate generateRootCertOld(KeyPair pair)
            throws Exception
    {

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

        X509v1CertificateBuilder builder = new X509v1CertificateBuilder(
                new X500Name("CN=Test CA Certificate"),
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test CA Certificate"),
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
        );

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }


    public static X509Certificate generateRootCert(KeyPair pair)
            throws Exception
    {

        X509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                new X500Name("CN=Test CA Certificate"),
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test CA Certificate"),
                pair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(pair.getPrivate());

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
    
    /**
     * Generate a sample V3 certificate to use as an intermediate CA certificate
     */
    public static X509Certificate generateIntermediateCertOld(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKey.getEncoded());

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);


        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(caCert.getSubjectDN().getName()),
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test Intermediate Certificate"),
                SubjectPublicKeyInfo.getInstance(intKey.getEncoded())
        );
        builder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(caCert.getPublicKey().getEncoded()));
        builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(intKey.getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }


    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
            throws Exception
    {

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert,
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test Intermediate Certificate"),
                intKey
        );

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caCert));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(intKey));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    /**
     * Generate a sample V3 certificate to use as an end entity certificate
     */
    public static X509Certificate generateEndEntityCertOld(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
	    throws Exception
	{
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1WithRSAEncryption");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKey.getEncoded());

        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);


        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(caCert.getSubjectDN().getName()),
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test End Certificate"),
                SubjectPublicKeyInfo.getInstance(entityKey.getEncoded())
        );
        builder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(caCert.getPublicKey().getEncoded()));
        builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(entityKey.getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
	}


    public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
            throws Exception
    {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCert,
                new BigInteger(64, new SecureRandom()),
                new Date(),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Name("CN=Test End Certificate"),
                entityKey
        );

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caCert));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(entityKey));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(caKey);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
}