package chapter7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Using the X509CRLSelector and the CertStore classes.
 */
public class CRLCertStoreExample
{
    public static void main(String[] args)
        throws Exception
    {
        // create CA keys and certificate
        KeyPair              caPair = Utils.generateRSAKeyPair();
        X509Certificate      caCert = /*Utils.generateRootCert(caPair)*/null;
        BigInteger           revokedSerialNumber = BigInteger.valueOf(2);
        
        // create a CRL revoking certificate number 2
        X509CRL	             crl = X509CRLExample.createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);
        
        // place the CRL into a CertStore
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(Collections.singleton(crl));
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");
        X509CRLSelector               selector = new X509CRLSelector();
        
        selector.addIssuerName(caCert.getSubjectX500Principal().getEncoded());
        
        Iterator                      it = store.getCRLs(selector).iterator();
        
        while (it.hasNext())
        {
            crl = (X509CRL)it.next();
            
            // verify the CRL
            crl.verify(caCert.getPublicKey(), "BC");
	        
            // check if the CRL revokes certificate number 2
            X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
            System.out.println("Revocation Details:");
            System.out.println("  Certificate number: " + entry.getSerialNumber());
            System.out.println("  Issuer            : " + crl.getIssuerX500Principal());
        }
    }
}
