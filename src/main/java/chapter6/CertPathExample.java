package chapter6;
 
import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Basic example of creating and encoding a CertPath.
 */
public class CertPathExample
{
	public static void main(
		String[] args)
	    throws Exception
	{
        X509Certificate[]   chain = /*PKCS10CertCreateExample.buildChain()*/null;
		
        // create the factory and path object
        CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");
        CertPath            certPath = fact.generateCertPath(Arrays.asList(chain));

        byte[] encoded = certPath.getEncoded("PEM");

        System.out.println(Utils.toString(encoded));
		
        // re-read the CertPath
        CertPath           newCertPath = fact.generateCertPath(new ByteArrayInputStream(encoded), "PEM");

        if (newCertPath.equals(certPath))
        {
            System.out.println("CertPath recovered correctly");
        }
    }
}
