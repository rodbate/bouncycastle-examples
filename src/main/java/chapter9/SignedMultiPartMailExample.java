package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.Arrays;

import javax.mail.BodyPart;
import javax.mail.Multipart;
import javax.mail.internet.*;

import org.bouncycastle.mail.smime.SMIMESigned;

/**
 * a simple example that creates and processes a signed mail message with multi-part contents.
 */
public class SignedMultiPartMailExample
    extends SignedDataProcessor
{
    public static void main(
        String args[])
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        CertStore       certsAndCRLs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(Arrays.asList(chain)), "BC");
        X509Certificate cert = (X509Certificate)chain[0];

        // create the message we want signed
        MimeBodyPart    dataPart1 = new MimeBodyPart();

        dataPart1.setText("Hello ");

        MimeBodyPart    dataPart2 = new MimeBodyPart();

        dataPart2.setText("World!");

        MimeMultipart dataMultiPart = new MimeMultipart();

        dataMultiPart.addBodyPart(dataPart1);
        dataMultiPart.addBodyPart(dataPart2);

        MimeBodyPart bodyPart = new MimeBodyPart();

        //
        // be careful about setting extra headers here. Some mail clients
        // ignore the To and From fields (for example) in the body part
        // that contains the multipart. The result of this will be that the
        // signature fails to verify... Outlook Express is an example of
        // a client that exhibits this behaviour.
        //
        bodyPart.setContent(dataMultiPart);
        
        // create the signed message
        MimeMultipart multiPart = SignedMailExample.createMultipartWithSignature(key, cert, certsAndCRLs, bodyPart);

        // create the mail message
        MimeMessage body = Utils.createMimeMessage("example signed message", multiPart, multiPart.getContentType());
body.writeTo(new java.io.FileOutputStream("test"));
        // extract the message from the mail message
        if (body.isMimeType("multipart/signed"))
        {
            SMIMESigned             signed = new SMIMESigned(
                                            (MimeMultipart)body.getContent());
            
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
            MimeBodyPart  content = signed.getContent();
            Multipart     cont = (Multipart)content.getContent();

            int count = cont.getCount();
            for (int i = 0; i < count; i++)
            {
                BodyPart    m = cont.getBodyPart(i);
                Object      part = m.getContent();

                System.out.println("Part " + i);
                System.out.println("----- begin -----");
                System.out.println(part);
                System.out.println("------ end ------");
            }
        }
    }
}
