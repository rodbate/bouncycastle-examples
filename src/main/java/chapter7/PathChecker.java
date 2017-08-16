package chapter7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.*;

class PathChecker
    extends PKIXCertPathChecker
{
    private KeyPair         responderPair;
    private X509Certificate caCert;
    private BigInteger      revokedSerialNumber;
    
    public PathChecker(
        KeyPair         responderPair,
        X509Certificate caCert,
        BigInteger      revokedSerialNumber)
    {
        this.responderPair = responderPair;
        this.caCert = caCert;
        this.revokedSerialNumber = revokedSerialNumber;
    }
    
    public void init(boolean forwardChecking)
        throws CertPathValidatorException
    {
        // ignore
    }

    public boolean isForwardCheckingSupported()
    {
        return true;
    }

    public Set getSupportedExtensions()
    {
        return null;
    }

    public void check(Certificate cert, Collection extensions)
        throws CertPathValidatorException
    {
        X509Certificate x509Cert = (X509Certificate)cert;
        
        /*try
        {
            String message = OCSPResponderExample.getStatusMessage(responderPair, caCert, revokedSerialNumber, x509Cert);
            
            if (message.endsWith("good"))
            {
                System.out.println(message);
            }
            else
            {
                throw new CertPathValidatorException(message);
            }
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException("exception verifying certificate: " + e, e);
        }*/
    }
}