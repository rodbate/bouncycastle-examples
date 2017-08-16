package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.Arrays;

import javax.mail.internet.*;

import org.bouncycastle.cms.*;
import org.bouncycastle.mail.smime.*;

/**
 * a simple example that creates and processes an enveloped signed mail message.
 */
public class EnvelopedSignedMailExample
    extends SignedDataProcessor
{
    public static void main(
        String[] args)
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        CertStore       certsAndCRLs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(Arrays.asList(chain)), "BC");
        X509Certificate cert = (X509Certificate)chain[0];

        // create the message we want signed
        MimeBodyPart    dataPart = new MimeBodyPart();

        dataPart.setText("Hello world!");
        
        // create the signed message
        MimeMultipart signedMultipart = SignedMailExample.createMultipartWithSignature(key, cert, certsAndCRLs, dataPart);

        // create the body part containing the signed message
        MimeBodyPart signedPart = new MimeBodyPart();

        signedPart.setContent(signedMultipart);
        
        // set up the enveloped message generator
        SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
          
        /*gen.addKeyTransRecipient(cert);

        // generate the enveloped message
        MimeBodyPart envPart = gen.generate(signedPart, SMIMEEnvelopedGenerator.AES256_CBC, "BC");

        // create the mail message
        MimeMessage mail = Utils.createMimeMessage("example signed and enveloped message", envPart.getContent(), envPart.getContentType());

        // create the enveloped object from the mail message
        SMIMEEnveloped     enveloped = new SMIMEEnveloped(mail);
        
        // look for our recipient identifier
        RecipientId        recId = new RecipientId();

        recId.setSerialNumber(cert.getSerialNumber());
        recId.setIssuer(cert.getIssuerX500Principal().getEncoded());

        RecipientInformationStore   recipients = enveloped.getRecipientInfos();
        RecipientInformation        recipient = recipients.get(recId);

        // decryption step
        MimeBodyPart        res = SMIMEUtil.toMimeBodyPart(recipient.getContent(key, "BC"));

        // extract the multi-part from the body part.
        if (res.getContent() instanceof MimeMultipart)
        {
            SMIMESigned     signed = new SMIMESigned(
                                            (MimeMultipart)res.getContent());

            // verification step
            X509Certificate rootCert = (X509Certificate)credentials.getCertificate(Utils.ROOT_ALIAS);
            
            if (isValid(signed, rootCert))
            {
                System.out.println("verification succeeded");
            }
            else
            {
                System.out.println("verification failed");
            }
            
            // content display step
            MimeBodyPart            content = signed.getContent();

            System.out.print("Content: ");
            System.out.println(content.getContent());
        }
        else
        {
            System.out.println("wrong content found");
        }*/
    }
}