package bcfipsin100.cmstsp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;

import bcfipsin100.base.EC;
import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import bcfipsin100.util.ExValues;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthenticatedData;
import org.bouncycastle.cms.CMSAuthenticatedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.KeyAgreeRecipientId;
import org.bouncycastle.cms.OriginatorInfoGenerator;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthenticatedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

public class Cms
{
    public static byte[] createSignedObject(PrivateKey signingKey, X509Certificate signingCert, byte[] data)
        throws GeneralSecurityException, OperatorCreationException, CMSException, IOException
    {
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData msg = new CMSProcessableByteArray(data);

        certList.add(signingCert);

        Store certs = new JcaCertStore(certList);

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(signingKey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(signer, signingCert));

        gen.addCertificates(certs);

        return gen.generate(msg, true).getEncoded();
    }

    public static boolean verifySignedObject(byte[] cmsSignedData)
        throws GeneralSecurityException, OperatorCreationException, CMSException
    {
        CMSSignedData          signedData = new CMSSignedData(cmsSignedData);
        Store                  certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(cert)))
            {
                return false;
            }
        }

        return true;
    }

    public static byte[] createDetachedSignature(PrivateKey signingKey, X509Certificate signingCert, byte[] data)
        throws GeneralSecurityException, OperatorCreationException, CMSException, IOException
    {
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData msg = new CMSProcessableByteArray(data);

        certList.add(signingCert);

        Store certs = new JcaCertStore(certList);

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(signingKey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(signer, signingCert));

        gen.addCertificates(certs);

        return gen.generate(msg).getEncoded();
    }

    public static boolean verifyDetachedData(byte[] cmsSignedData, byte[] data)
        throws GeneralSecurityException, OperatorCreationException, CMSException
    {
        CMSSignedData          signedData = new CMSSignedData(new CMSProcessableByteArray(data), cmsSignedData);
        Store                  certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(cert)))
            {
                return false;
            }
        }

        return true;
    }

    public static byte[] createCounterSignedData(PrivateKey signingKey, X509Certificate signingCert, byte[] data, PrivateKey counterSignerKey, X509Certificate counterSignerCert)
        throws OperatorCreationException, GeneralSecurityException, CMSException, IOException
    {
        CMSSignedData signedData = new CMSSignedData(createSignedObject(signingKey, signingCert, data));

        SignerInformation signer = signedData.getSignerInfos().iterator().next();

        CMSSignedDataGenerator counterSignerGen = new CMSSignedDataGenerator();

        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digProvider);

        counterSignerGen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(new JcaContentSignerBuilder("SHA384withRSA").setProvider("BCFIPS").build(counterSignerKey), counterSignerCert));

        SignerInformationStore counterSigners = counterSignerGen.generateCounterSigners(signer);

        signer = SignerInformation.addCounterSigners(signer, counterSigners);

        CMSSignedDataGenerator signerGen = new CMSSignedDataGenerator();

        signerGen.addCertificate(new JcaX509CertificateHolder(signingCert));
        signerGen.addCertificate(new JcaX509CertificateHolder(counterSignerCert));

        signerGen.addSigners(new SignerInformationStore(signer));

        return signerGen.generate(new CMSProcessableByteArray(data), true).getEncoded();
    }

    public static boolean verifyCounterSignature(byte[] cmsSignedData)
        throws OperatorCreationException, GeneralSecurityException, CMSException, IOException
    {
        CMSSignedData         signedData = new CMSSignedData(cmsSignedData);
        SignerInformation     signer = signedData.getSignerInfos().iterator().next();
        SignerInformation     counterSigner = signer.getCounterSignatures().iterator().next();
        Collection            certCollection = signedData.getCertificates().getMatches(counterSigner.getSID());
        Iterator              certIt = certCollection.iterator();
        X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

        return counterSigner.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(cert));
    }

    public static Attribute createTspAttribute(PrivateKey tspSigningKey, X509Certificate tspSignerCert, byte[] data)
        throws GeneralSecurityException, OperatorCreationException, TSPException, IOException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-384", "BCFIPS");
        TimeStampResponse response = new TimeStampResponse(Tsp.createTspResponse(tspSigningKey, tspSignerCert, Tsp.createTspRequest(digest.digest(data))));
        TimeStampToken timestampToken = response.getTimeStampToken();

        return new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(timestampToken.toCMSSignedData().toASN1Structure()));
    }

    public static byte[] createTimeStampedSigner(PrivateKey signingKey, X509Certificate signingCert, byte[] data, PrivateKey tspSigningKey, X509Certificate tspSignerCert)
        throws OperatorCreationException, GeneralSecurityException, CMSException, TSPException, IOException
    {
        CMSSignedData signedData = new CMSSignedData(createSignedObject(signingKey, signingCert, data));

        SignerInformation signer = signedData.getSignerInfos().iterator().next();

        ASN1EncodableVector timestampVector = new ASN1EncodableVector();
        timestampVector.add(createTspAttribute(tspSigningKey, tspSignerCert, signer.getSignature()));
        AttributeTable at = new AttributeTable(timestampVector);

        signer = SignerInformation.replaceUnsignedAttributes(signer, at);

        SignerInformationStore newSignerStore = new SignerInformationStore(signer);

        return CMSSignedData.replaceSigners(signedData, newSignerStore).getEncoded();
    }

    public static boolean verifyTimeStampedSigner(byte[] cmsSignedData)
        throws OperatorCreationException, GeneralSecurityException, CMSException, IOException, TSPException
    {
        CMSSignedData         signedData = new CMSSignedData(cmsSignedData);
        SignerInformation     signer = signedData.getSignerInfos().iterator().next();
        TimeStampToken        tspToken = new TimeStampToken(ContentInfo.getInstance(signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttributeValues()[0]));
        Collection            certCollection = tspToken.getCertificates().getMatches(tspToken.getSID());
        Iterator              certIt = certCollection.iterator();
        X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

        tspToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(cert));

        return true;
    }

    public static byte[] createKeyTransEnvelopedObject(X509Certificate encryptionCert, byte[] data)
        throws GeneralSecurityException, CMSException, IOException
    {
        CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();
        JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();

        envelopedGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert, paramsConverter.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT)).setProvider("BCFIPS"));

        return envelopedGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build()).getEncoded();
    }

    public static byte[] extractKeyTransEnvelopedData(PrivateKey privateKey, X509Certificate encryptionCert, byte[] encEnvelopedData)
        throws CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();

        Collection c = recipients.getRecipients(new JceKeyTransRecipientId(encryptionCert));

        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            return recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BCFIPS"));
        }

        throw new IllegalArgumentException("recipient for certificate not found");
    }

    public static byte[] createKeyAgreeEnvelopedObject(PrivateKey initiatorKey, X509Certificate initiatorCert, X509Certificate recipientCert, byte[] data)
        throws GeneralSecurityException, CMSException, IOException
    {
        CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();

        envelopedGen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECCDH_SHA384KDF,
            initiatorKey, initiatorCert.getPublicKey(),
            CMSAlgorithm.AES256_WRAP).addRecipient(recipientCert).setProvider("BCFIPS"));

        return envelopedGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build()).getEncoded();

    }

    public static byte[] extractKeyAgreeEnvelopedData(PrivateKey recipientKey, X509Certificate recipientCert, byte[] encEnvelopedData)
        throws GeneralSecurityException, CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new JceKeyAgreeRecipientId(recipientCert);

        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(new JceKeyAgreeEnvelopedRecipient(recipientKey).setProvider("BCFIPS"));
    }

    public static byte[] createKekEnvelopedObject(byte[] keyID, SecretKey keyEncryptionKey, byte[] data)
        throws GeneralSecurityException, CMSException, IOException
    {
        CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();

        envelopedGen.addRecipientInfoGenerator(
            new JceKEKRecipientInfoGenerator(keyID, keyEncryptionKey));

        return envelopedGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build()).getEncoded();
    }

    public static byte[] extractKekEnvelopedData(byte[] keyID, SecretKey keyEncryptionKey, byte[] encEnvelopedData)
        throws GeneralSecurityException, CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new KEKRecipientId(keyID);

        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
            new JceKEKEnvelopedRecipient(keyEncryptionKey)
            .setProvider("BCFIPS"));
    }

    public static byte[] createPasswordEnvelopedObject(char[] passwd, byte[] salt, int iterationCount, byte[] data)
        throws GeneralSecurityException, CMSException, IOException
    {
        CMSEnvelopedDataGenerator envelopedGen = new CMSEnvelopedDataGenerator();

        envelopedGen.addRecipientInfoGenerator(
            new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC, passwd)
            .setProvider("BCFIPS")
            .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8)
            .setPRF(PasswordRecipient.PRF.HMacSHA384)
            .setSaltAndIterationCount(salt, iterationCount));

        return envelopedGen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build()).getEncoded();
    }

    public static byte[] extractPasswordEnvelopedData(char[] passwd, byte[] encEnvelopedData)
        throws GeneralSecurityException, CMSException
    {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encEnvelopedData);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new PasswordRecipientId();

        RecipientInformation recipient = recipients.get(rid);

        return recipient.getContent(
            new JcePasswordEnvelopedRecipient(passwd)
            .setProvider("BCFIPS")
            .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8));
    }

    public static byte[] createAuthenticatedData(X509Certificate originatorCertificate, X509Certificate recipientCertificate, byte[] data)
        throws GeneralSecurityException, CMSException, IOException
    {
        ASN1ObjectIdentifier macAlg = CMSAlgorithm.DES_EDE3_CBC;

        CMSAuthenticatedDataGenerator authDataGenerator = new CMSAuthenticatedDataGenerator();

        X509CertificateHolder origCert = new JcaX509CertificateHolder(originatorCertificate);

        authDataGenerator.setOriginatorInfo(new OriginatorInfoGenerator(origCert).generate());

        authDataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCertificate).setProvider("BCFIPS"));

        return authDataGenerator.generate(
                                new CMSProcessableByteArray(data),
                                new JceCMSMacCalculatorBuilder(macAlg).setProvider("BCFIPS").build()).getEncoded();
    }

    public static byte[] extractAuthenticatedData(PrivateKey recipientPrivateKey, X509Certificate recipientCert, byte[] encAuthData)
        throws GeneralSecurityException, CMSException
    {
        CMSAuthenticatedData authData = new CMSAuthenticatedData(encAuthData);

        RecipientInformationStore recipients = authData.getRecipientInfos();

        RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(recipientCert));

        if (recipient != null)
        {
            byte[] recData = recipient.getContent(new JceKeyTransAuthenticatedRecipient(recipientPrivateKey).setProvider("BCFIPS"));

            if (Arrays.constantTimeAreEqual(authData.getMac(), recipient.getMac()))
            {
                return recData;
            }
            else
            {
                throw new IllegalStateException("MAC check failed");
            }
        }

        throw new IllegalStateException("no recipient found");
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, CMSException, IOException, TSPException
    {
        Setup.installProvider();

        KeyPair ecSigningKeyPair = EC.generateKeyPair();
        KeyPair ecEncryptionKeyPair1 = EC.generateKeyPair();
        KeyPair ecEncryptionKeyPair2 = EC.generateKeyPair();
        KeyPair rsaSigningKeyPair = Rsa.generateKeyPair();
        KeyPair rsaEncryptionKeyPair = Rsa.generateKeyPair();

        X509Certificate ecSigningCert = Cert.makeV1Certificate(ecSigningKeyPair.getPrivate(), ecSigningKeyPair.getPublic());
        X509Certificate ecEncryptionCert1 = Cert.makeV1Certificate(ecSigningKeyPair.getPrivate(), ecEncryptionKeyPair1.getPublic());
        X509Certificate ecEncryptionCert2 = Cert.makeV1Certificate(ecSigningKeyPair.getPrivate(), ecEncryptionKeyPair2.getPublic());
        X509Certificate rsaSigningCert = Cert.makeV1RsaCertificate(rsaSigningKeyPair.getPrivate(), rsaSigningKeyPair.getPublic());
        X509Certificate rsaEncryptionCert = Cert.makeV1RsaCertificate(rsaSigningKeyPair.getPrivate(), rsaEncryptionKeyPair.getPublic());

        System.err.println(verifySignedObject(createSignedObject(ecSigningKeyPair.getPrivate(), ecSigningCert, ExValues.SampleInput)));
        System.err.println(verifyDetachedData(createDetachedSignature(ecSigningKeyPair.getPrivate(), ecSigningCert, ExValues.SampleInput), ExValues.SampleInput));
        System.err.println(verifyCounterSignature(createCounterSignedData(ecSigningKeyPair.getPrivate(), ecSigningCert, ExValues.SampleInput, rsaSigningKeyPair.getPrivate(), rsaSigningCert)));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractKeyTransEnvelopedData(rsaEncryptionKeyPair.getPrivate(), rsaEncryptionCert, createKeyTransEnvelopedObject(rsaEncryptionCert, ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractKeyAgreeEnvelopedData(ecEncryptionKeyPair2.getPrivate(), ecEncryptionCert2, createKeyAgreeEnvelopedObject(ecEncryptionKeyPair1.getPrivate(), ecEncryptionCert1, ecEncryptionCert2, ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractPasswordEnvelopedData("password".toCharArray(), createPasswordEnvelopedObject("password".toCharArray(), Hex.decode("000102030405060708090a0b0c0d0e0f"), 1024, ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractKekEnvelopedData(new byte[4], ExValues.SampleAesKey, createKekEnvelopedObject(new byte[4], ExValues.SampleAesKey, ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractAuthenticatedData(rsaEncryptionKeyPair.getPrivate(), rsaEncryptionCert, createAuthenticatedData(rsaSigningCert, rsaEncryptionCert, ExValues.SampleInput))));
        System.err.println(verifyTimeStampedSigner(createTimeStampedSigner(ecSigningKeyPair.getPrivate(), ecSigningCert, ExValues.SampleInput, rsaSigningKeyPair.getPrivate(), Cert.makeRsaTspCertificate(rsaSigningCert, rsaSigningKeyPair.getPrivate(), rsaSigningKeyPair.getPublic()))));
    }
}
