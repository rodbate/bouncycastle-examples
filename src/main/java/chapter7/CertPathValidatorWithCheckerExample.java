package chapter7;
 
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.*;
import java.util.*;

/**
 * Basic example of certificate path validation using a PKIXCertPathChecker
 */
public class CertPathValidatorWithCheckerExample
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
        
        BigInteger      revokedSerialNumber = BigInteger.valueOf(3);
        
        // create CertStore to support validation
        List list = new ArrayList();
        
        list.add(rootCert);
        list.add(interCert);
        list.add(endCert);
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters( list );
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // create certificate path
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        List               certChain = new ArrayList();

        certChain.add(endCert);
        certChain.add(interCert);

        CertPath certPath = fact.generateCertPath(certChain);
        Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));

        // perform validation
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters    param = new PKIXParameters(trust);
        
        param.addCertPathChecker(new PathChecker(rootPair, rootCert, revokedSerialNumber));
        param.setRevocationEnabled(false);
        param.addCertStore(store);
        param.setDate(new Date());
        
        try
        {
            CertPathValidatorResult result = validator.validate(certPath, param);

            System.out.println("certificate path validated");
        }
        catch (CertPathValidatorException e)
        {
            System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
        }*/
    }
}

