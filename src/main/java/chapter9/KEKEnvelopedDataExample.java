package chapter9;

import java.util.Arrays;

import javax.crypto.*;

import org.bouncycastle.cms.*;

/**
 * Demonstrate creation and processing a key-encrypted key enveloped-message.
 */
public class KEKEnvelopedDataExample
{
    public static void main(String[] args)
        throws Exception
    {
        /*KeyGenerator    keyGen = KeyGenerator.getInstance("DESEDE", "BC");
        SecretKey       key  = keyGen.generateKey();
        
        // set up the generator
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekID = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(key, kekID);

        // create the enveloped-data object
        CMSProcessable  data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSEnvelopedData enveloped = edGen.generate(
                                data,
                                CMSEnvelopedDataGenerator.AES128_CBC, "BC");
        // recreate
        enveloped = new CMSEnvelopedData(enveloped.getEncoded());

        // look for our recipient
        RecipientId     recId = new RecipientId();

        recId.setKeyIdentifier(kekID);

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