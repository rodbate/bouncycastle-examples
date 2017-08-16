package chapter7;
 
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Basic example of the use of CertPathBuilder.
 */
public class CertPathBuilderExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = Utils.generateRSAKeyPair();
        KeyPair         interPair = Utils.generateRSAKeyPair();
        KeyPair         endPair = Utils.generateRSAKeyPair();
        
        /*X509Certificate rootCert = Utils.generateRootCert(rootPair);
        X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = Utils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
        
        BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
        X509CRL         rootCRL = X509CRLExample.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
        X509CRL         interCRL = X509CRLExample.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
        
        // create CertStore to support path building
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        list.add(rootCRL);
        list.add(interCRL);
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector endConstraints = new X509CertSelector();
        
        endConstraints.setSerialNumber(endCert.getSerialNumber());
        endConstraints.setIssuer(endCert.getIssuerX500Principal().getEncoded());
        
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);
        
        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        Iterator it = path.getCertificates().iterator();
        while (it.hasNext())
        {
            System.out.println(((X509Certificate)it.next()).getSubjectX500Principal());
        }
        
        System.out.println(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());*/
    }
}
