package bcfipsin100.pbeks;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

public class Pem
{
    public static String writeCertificate(X509Certificate certificate)
        throws IOException
    {
        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);

        pemWriter.writeObject(certificate);

        pemWriter.close();

        return sWrt.toString();
    }

    public static X509Certificate readCertificate(String pemEncoding)
        throws IOException, CertificateException
    {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        X509CertificateHolder certHolder = (X509CertificateHolder)parser.readObject();

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public static String writePrivateKey(PrivateKey privateKey)
        throws IOException
    {
        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);

        pemWriter.writeObject(privateKey);

        pemWriter.close();

        return sWrt.toString();
    }

    public static PrivateKey readPrivateKey(String pemEncoding)
        throws IOException, CertificateException
    {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        PEMKeyPair pemKeyPair = (PEMKeyPair)parser.readObject();

        return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

    public static String writeEncryptedKey(char[] passwd, PrivateKey privateKey)
        throws IOException, OperatorCreationException
    {
        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);

        PKCS8EncryptedPrivateKeyInfoBuilder pkcs8Builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);

        pemWriter.writeObject(pkcs8Builder.build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider("BCFIPS").build(passwd)));

        pemWriter.close();

        return sWrt.toString();
    }

    public static PrivateKey readEncryptedKey(char[] password, String pemEncoding)
        throws IOException, OperatorCreationException, PKCSException
    {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        PKCS8EncryptedPrivateKeyInfo encPrivKeyInfo = (PKCS8EncryptedPrivateKeyInfo)parser.readObject();

        InputDecryptorProvider pkcs8Prov = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BCFIPS").build(password);

        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider("BCFIPS");

        return converter.getPrivateKey(encPrivKeyInfo.decryptPrivateKeyInfo(pkcs8Prov));
    }

    public static String writeEncryptedKeyOpenSsl(char[] passwd, PrivateKey privateKey)
        throws IOException, OperatorCreationException
    {
        StringWriter sWrt = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt);

        pemWriter.writeObject(privateKey, new JcePEMEncryptorBuilder("AES-256-CBC").setProvider("BCFIPS").build(passwd));

        pemWriter.close();

        return sWrt.toString();
    }

    public static PrivateKey readEncryptedKeyOpenSsl(char[] passwd, String pemEncoding)
        throws IOException, OperatorCreationException
    {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        PEMEncryptedKeyPair pemEncryptedKeyPair = (PEMEncryptedKeyPair)parser.readObject();

        PEMDecryptorProvider pkcs8Prov = new JcePEMDecryptorProviderBuilder().setProvider("BCFIPS").build(passwd);

        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider("BCFIPS");

        return converter.getPrivateKey(pemEncryptedKeyPair.decryptKeyPair(pkcs8Prov).getPrivateKeyInfo());
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException
    {
        Setup.installProvider();

        KeyPair keyPair = EC.generateKeyPair();

        X509Certificate certificate = Cert.makeV1Certificate(keyPair.getPrivate(), keyPair.getPublic());

        char[] keyPass = "keyPassword".toCharArray();

        String pemCertificate = writeCertificate(certificate);
        System.err.println(pemCertificate);
        System.err.println(certificate.equals(readCertificate(pemCertificate)));

        String pemPrivateKey = writePrivateKey(keyPair.getPrivate());
        System.err.println(pemPrivateKey);
        System.err.println(keyPair.getPrivate().equals(readPrivateKey(pemPrivateKey)));

        String encPrivKey = writeEncryptedKey(keyPass, keyPair.getPrivate());

        System.err.println(encPrivKey);
        System.err.println(keyPair.getPrivate().equals(readEncryptedKey(keyPass, encPrivKey)));

        String openSslEncPrivKey = writeEncryptedKeyOpenSsl(keyPass, keyPair.getPrivate());

        System.err.println(openSslEncPrivKey);
        System.err.println(keyPair.getPrivate().equals(readEncryptedKeyOpenSsl(keyPass, openSslEncPrivKey)));
    }
}
