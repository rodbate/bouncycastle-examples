package bcfipsin100.pbeks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import bcfipsin100.util.ExValues;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

public class KeyStr
{
    public static byte[] storeCertificate(char[] storePassword, X509Certificate trustedCert)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry("trustedca", trustedCert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, storePassword);

        return bOut.toByteArray();
    }

    public static byte[] storePrivateKey(char[] storePassword, char[] keyPass, PrivateKey eeKey, X509Certificate[] eeCertChain)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("jks");

        keyStore.load(null, null);

        keyStore.setKeyEntry("key", eeKey, keyPass, eeCertChain);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, storePassword);

        return bOut.toByteArray();
    }

    public static byte[] storeSecretKey(char[] storePassword, char[] keyPass, SecretKey secretKey)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");

        keyStore.load(null, null);

        keyStore.setKeyEntry("secretkey", secretKey, keyPass, null);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, storePassword);

        return bOut.toByteArray();
    }

    public static byte[] storeCertificatePkcs12(char[] storePassword, X509Certificate trustedCert)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BCFIPS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry("trustedca", trustedCert);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, storePassword);

        return bOut.toByteArray();
    }

    public static byte[] storePrivateKeyPkcs12(char[] storePassword, PrivateKey eeKey, X509Certificate[] eeCertChain)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BCFIPS");

        keyStore.load(null, null);

        keyStore.setKeyEntry("key", eeKey, null, eeCertChain);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        keyStore.store(bOut, storePassword);

        return bOut.toByteArray();
    }

    public static byte[] createPfxPdu(char[] passwd, PrivateKey privKey, X509Certificate[] certs)
        throws GeneralSecurityException, OperatorCreationException, PKCSException, IOException
    {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(certs[1]);

        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("CA Certificate"));

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(certs[0]);

        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("End Entity Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(certs[0].getPublicKey()));

        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey, new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC).setProvider("BCFIPS").build(passwd));

        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("End Entity Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(certs[0].getPublicKey()));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

        PKCS12SafeBag[] safeBags = new PKCS12SafeBag[2];

        safeBags[0] = eeCertBagBuilder.build();
        safeBags[1] = caCertBagBuilder.build();

        pfxPduBuilder.addEncryptedData(new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC).setProvider("BCFIPS").build(passwd), safeBags);

        pfxPduBuilder.addData(keyBagBuilder.build());

        return pfxPduBuilder.build(new JcePKCS12MacCalculatorBuilder().setProvider("BCFIPS"), passwd).getEncoded();
    }

    private static KeyStore rebuildStore(String storeType, char[] storePassword, byte[] encoding)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance(storeType, "BCFIPS");

        keyStore.load(new ByteArrayInputStream(encoding), storePassword);

        return keyStore;
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, PKCSException, IOException
    {
        Setup.installProvider();

        KeyPair caKeyPair = EC.generateKeyPair();
        KeyPair eeKeyPair = EC.generateKeyPair();

        X509Certificate caCert = Cert.makeV1Certificate(caKeyPair.getPrivate(), caKeyPair.getPublic());
        X509Certificate eeCert = Cert.makeV3Certificate(caCert, caKeyPair.getPrivate(), eeKeyPair.getPublic());

        char[] storePass = "storePassword".toCharArray();
        char[] keyPass = "keyPassword".toCharArray();

        System.err.println("BCFKS (certificate  : " + rebuildStore("BCFKS", storePass, storeCertificate(storePass, caCert)).isCertificateEntry("trustedca"));
        System.err.println("BCFKS (key)         : " + rebuildStore("BCFKS", storePass, storePrivateKey(storePass, keyPass, eeKeyPair.getPrivate(), new X509Certificate[] { eeCert })).isKeyEntry("key"));
        System.err.println("BCFKS (key)         : " + rebuildStore("BCFKS", storePass, storeSecretKey(storePass, keyPass, ExValues.SampleAesKey)).isKeyEntry("secretkey"));
        System.err.println("PKCS12 (certificate): " + rebuildStore("PKCS12", storePass, storeCertificatePkcs12(storePass, caCert)).isCertificateEntry("trustedca"));
        System.err.println("PKCS12 (key)        : " + rebuildStore("PKCS12", storePass, storePrivateKeyPkcs12(storePass, eeKeyPair.getPrivate(), new X509Certificate[] { eeCert })).isKeyEntry("key"));
        System.err.println("PKCS12 (key)        : " + rebuildStore("PKCS12", storePass, createPfxPdu(storePass, eeKeyPair.getPrivate(), new X509Certificate[] { eeCert, caCert })).isKeyEntry("End Entity Key"));
    }
}
