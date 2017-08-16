package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;

/**
 * a simple example that creates and processes an enveloped mail message.
 */
public class EnvelopedMailExample
{
    public static void main(
        String args[])
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        X509Certificate cert = (X509Certificate)chain[0];

        // create the message we want encrypted
        MimeBodyPart    dataPart = new MimeBodyPart();

        dataPart.setText("Hello world!");
        
        // set up the generator
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        /*gen.addKeyTransRecipient(cert);

        // generate the enveloped message
        MimeBodyPart envPart = gen.generate(dataPart, SMIMEEnvelopedGenerator.AES256_CBC, "BC");

        // create the mail message
        MimeMessage mail = Utils.createMimeMessage("example enveloped message", envPart.getContent(), envPart.getContentType());

        // create the enveloped object from the mail message
        SMIMEEnveloped  enveloped = new SMIMEEnveloped(mail);
        
        // look for our recipient identifier
        RecipientId     recId = new RecipientId();

        recId.setSerialNumber(cert.getSerialNumber());
        recId.setIssuer(cert.getIssuerX500Principal().getEncoded());

        RecipientInformationStore   recipients = enveloped.getRecipientInfos();
        RecipientInformation        recipient = recipients.get(recId);

        if (recipient != null)
        {
            // decryption step
            MimeBodyPart     recoveredPart = SMIMEUtil.toMimeBodyPart(recipient.getContent(key, "BC"));

            // content display step
            System.out.print("Content: ");
            System.out.println(recoveredPart.getContent());
        }
        else
        {
            System.out.println("could not find a matching recipient");
        }*/
    }
}