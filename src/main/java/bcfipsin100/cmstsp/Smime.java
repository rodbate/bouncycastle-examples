package bcfipsin100.cmstsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

public class Smime
{
    private static ASN1EncodableVector generateSignedAttributes()
    {
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.aES128_CBC);
        caps.addCapability(SMIMECapability.aES192_CBC);
        caps.addCapability(SMIMECapability.aES256_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        return signedAttrs;
    }

    public static MimeMultipart createSignedMultipart(PrivateKey signingKey, X509Certificate signingCert, MimeBodyPart message)
        throws GeneralSecurityException, OperatorCreationException, SMIMEException, IOException
    {
        List<X509Certificate> certList = new ArrayList<X509Certificate>();

        certList.add(signingCert);

        Store certs = new JcaCertStore(certList);

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                                            .setProvider("BCFIPS")
                                            .setSignedAttributeGenerator(new AttributeTable(signedAttrs))
                                            .build("SHA384withRSAandMGF1", signingKey, signingCert));
        gen.addCertificates(certs);

        return gen.generate(message);
    }

    public static boolean verifySignedMultipart(MimeMultipart signedMessage)
        throws GeneralSecurityException, OperatorCreationException, CMSException, SMIMEException, MessagingException
    {
        SMIMESigned            signedData = new SMIMESigned(signedMessage);
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

    public static MimeBodyPart createEnvelopedBodyPart(X509Certificate encryptionCert, MimeBodyPart message)
        throws GeneralSecurityException, SMIMEException, CMSException, IOException
    {
        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert).setProvider("BCFIPS"));

        return gen.generate(message, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build());
    }

    public static MimeBodyPart extractEnvelopedBodyPart(PrivateKey privateKey, X509Certificate encryptionCert, MimeBodyPart envelopedBodyPart)
        throws SMIMEException, CMSException, MessagingException
    {
        SMIMEEnveloped envelopedData = new SMIMEEnveloped(envelopedBodyPart);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();

        Collection c = recipients.getRecipients(new JceKeyTransRecipientId(encryptionCert));

        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            return SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BCFIPS")));
        }

        throw new IllegalArgumentException("recipient for certificate not found");
    }

    public static MimeBodyPart createSignedEncryptedBodyPart(PrivateKey signingKey, X509Certificate signingCert, X509Certificate encryptionCert, MimeBodyPart message)
        throws GeneralSecurityException, SMIMEException, CMSException, IOException, OperatorCreationException, MessagingException
    {
        SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();

        gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encryptionCert).setProvider("BCFIPS"));

        MimeBodyPart bodyPart = new MimeBodyPart();

        bodyPart.setContent(createSignedMultipart(signingKey, signingCert, message));

        return gen.generate(bodyPart, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BCFIPS").build());
    }

    public static boolean verifySignedEncryptedBodyPart(PrivateKey privateKey, X509Certificate encryptionCert, MimeBodyPart envelopedBodyPart)
        throws SMIMEException, CMSException, GeneralSecurityException, OperatorCreationException, MessagingException, IOException
    {
        SMIMEEnveloped envelopedData = new SMIMEEnveloped(envelopedBodyPart);
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();

        Collection c = recipients.getRecipients(new JceKeyTransRecipientId(encryptionCert));

        Iterator it = c.iterator();

        if (it.hasNext())
        {
            RecipientInformation recipient = (RecipientInformation)it.next();

            MimeBodyPart signedPart = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BCFIPS")));

            return verifySignedMultipart((MimeMultipart)signedPart.getContent());
        }

        throw new IllegalArgumentException("recipient for certificate not found");
    }

    private static byte[] toByteArray(MimeBodyPart bodyPart)
        throws IOException, MessagingException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bodyPart.writeTo(bOut);
        bOut.close();
        return bOut.toByteArray();
    }

    public static void main(String[] args)
        throws Exception
    {
        Setup.installProvider();

        KeyPair rsaSigningKeyPair = Rsa.generateKeyPair();
        KeyPair rsaEncryptionKeyPair = Rsa.generateKeyPair();

        X509Certificate rsaSigningCert = Cert.makeV1RsaCertificate(rsaSigningKeyPair.getPrivate(), rsaSigningKeyPair.getPublic());
        X509Certificate rsaEncryptionCert = Cert.makeV1RsaCertificate(rsaSigningKeyPair.getPrivate(), rsaEncryptionKeyPair.getPublic());

        MimeBodyPart mimeBodyPart = new MimeBodyPart();

        mimeBodyPart.setText("Hello World!");

        System.err.println(verifySignedMultipart(createSignedMultipart(rsaSigningKeyPair.getPrivate(), rsaSigningCert, mimeBodyPart)));
        System.err.println(Arrays.areEqual(toByteArray(mimeBodyPart), toByteArray(extractEnvelopedBodyPart(rsaEncryptionKeyPair.getPrivate(), rsaEncryptionCert, createEnvelopedBodyPart(rsaEncryptionCert, mimeBodyPart)))));
        System.err.println(verifySignedEncryptedBodyPart(rsaEncryptionKeyPair.getPrivate(), rsaEncryptionCert, createSignedEncryptedBodyPart(rsaSigningKeyPair.getPrivate(), rsaSigningCert, rsaEncryptionCert, mimeBodyPart)));
    }
}
