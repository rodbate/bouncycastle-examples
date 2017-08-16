package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

/**
 * Demonstrate creation and processing a public key recipient enveloped-message
 * with matching of the RID to a certificate to make sure we have the right recipient.
 */
public class KeyTransEnvelopedDataWithCertMatchExample
{
    public static void main(String[] args)
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        X509Certificate cert = (X509Certificate)chain[0];

        // set up the generator
        /*CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        
        gen.addKeyTransRecipient(cert);
        
        // create the enveloped-data object
        CMSProcessable   data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSEnvelopedData enveloped = gen.generate(
                                data,
                                CMSEnvelopedDataGenerator.AES256_CBC, "BC");
        
        // recreate
        enveloped = new CMSEnvelopedData(enveloped.getEncoded());
        
        // set up to iterate through the recipients
        RecipientInformationStore   recipients = enveloped.getRecipientInfos();
        CertStore                   certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Collections.singleton(cert)), "BC");
        Iterator                    it = recipients.getRecipients().iterator();
        RecipientInformation        recipient = null;
        
        while (it.hasNext())
        {
            recipient = (RecipientInformation)it.next();
            if (recipient instanceof KeyTransRecipientInformation)
            {
                // match the recipient ID
                Collection matches = certStore.getCertificates(recipient.getRID());
                
                if (!matches.isEmpty())
                {
                    // decrypt the data
                    byte[] recData = recipient.getContent(key, "BC");

                    // compare recovered data to the original data
                    if (Arrays.equals((byte[])data.getContent(), recData))
                    {
                        System.out.println("data recovery succeeded");
                        break;
                    }
                    else
                    {
                        System.out.println("data recovery failed");
                        break;
                    }
                }
            }
        }   
        
        if (recipient == null)
        {
            System.out.println("could not find a matching recipient");
        }*/
    }
}