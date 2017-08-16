package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

/**
 * Demonstrate creation and processing a public key recipient enveloped-message.
 */
public class KeyTransEnvelopedDataExample
{
    public static void main(String[] args)
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        X509Certificate cert = (X509Certificate)chain[0];

        // set up the generator
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        
        /*gen.addKeyTransRecipient(cert);
        
        // create the enveloped-data object
        CMSProcessable   data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSEnvelopedData enveloped = gen.generate(
                                data,
                                CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        // recreate
        enveloped = new CMSEnvelopedData(enveloped.getEncoded());
        
        // look for our recipient identifier
        RecipientId     recId = new RecipientId();

        recId.setSerialNumber(cert.getSerialNumber());
        recId.setIssuer(cert.getIssuerX500Principal().getEncoded());

        RecipientInformationStore   recipients = enveloped.getRecipientInfos();
        RecipientInformation        recipient = recipients.get(recId);
        
        if (recipient != null)
        {
            // decrypt the data
            byte[] recData = recipient.getContent(key, "BC");

            // compare recovered data to the original data
            if (Arrays.equals((byte[])data.getContent(), recData))
            {
                System.out.println("data recovery succeeded");
            }
            else
            {
                System.out.println("data recovery failed");
            }
        }
        else
        {
            System.out.println("could not find a matching recipient");
        }*/
    }
}