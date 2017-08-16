package chapter9;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.Arrays;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Example of generating a detached signature.
 */
public class SignedDataExample
    extends SignedDataProcessor
{
    public static void main(String[] args)
        throws Exception
    {
        KeyStore        credentials = Utils.createCredentials();
        PrivateKey      key = (PrivateKey)credentials.getKey(Utils.END_ENTITY_ALIAS, Utils.KEY_PASSWD);
        Certificate[]   chain = credentials.getCertificateChain(Utils.END_ENTITY_ALIAS);
        CertStore       certsAndCRLs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(Arrays.asList(chain)), "BC");
        X509Certificate cert = (X509Certificate)chain[0];

        // set up the generator
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        /*gen.addSigner(key, cert, CMSSignedDataGenerator.DIGEST_SHA224);

        gen.addCertificatesAndCRLs(certsAndCRLs);
        
        // create the signed-data object
        CMSProcessable  data = new CMSProcessableByteArray("Hello World!".getBytes());

        CMSSignedData signed = gen.generate(data, "BC");
        
        // recreate
        signed = new CMSSignedData(data, signed.getEncoded());
        
        // verification step
        X509Certificate rootCert = (X509Certificate)credentials.getCertificate(Utils.ROOT_ALIAS);

        if (isValid(signed, rootCert))
        {
            System.out.println("verification succeeded");
        }
        else
        {
            System.out.println("verification failed");
        }*/
    }
}
