package chapter6;

import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

/**
 * Example using a CertStore and a CertSelector
 */
public class CertStoreExample
{
    public static void main(String[] args)
        throws Exception
    {
        X509Certificate[]   chain = /*PKCS10CertCreateExample.buildChain()*/null;
        
        // create the store
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
        CertStore store = CertStore.getInstance("Collection", params, "BC");
        
        // create the selector
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(new X500Principal("CN=Requested Test Certificate").getEncoded());

        // print the subjects of the results
        Iterator certsIt = store.getCertificates(selector).iterator();
        while (certsIt.hasNext()) 
        {
            X509Certificate cert = (X509Certificate)certsIt.next();
            
            System.out.println(cert.getSubjectX500Principal());
        }
    }
}