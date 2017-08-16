package chapter7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.*;

/**
 * Basic Example of generating and using a CRL.
 */
public class X509CRLExample
{
    public static X509CRL createCRL(
        X509Certificate caCert, 
        PrivateKey      caKey, 
        BigInteger      revokedSerialNumber)
        throws Exception
    {
        X509V2CRLGenerator   crlGen = new X509V2CRLGenerator();
        Date                 now = new Date();
        
        crlGen.setIssuerDN(caCert.getSubjectX500Principal());
        
        crlGen.setThisUpdate(now);
        crlGen.setNextUpdate(new Date(now.getTime() + 100000));
        crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        crlGen.addCRLEntry(revokedSerialNumber, now, CRLReason.privilegeWithdrawn);
        
        crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        
        return crlGen.generateX509CRL(caKey, "BC");
    }
    
    public static void main(String[] args)
        throws Exception
    {
        // create CA keys and certificate
        KeyPair              caPair = Utils.generateRSAKeyPair();
        X509Certificate      caCert = /*Utils.generateRootCert(caPair)*/null;
        BigInteger           revokedSerialNumber = BigInteger.valueOf(2);
        
        // create a CRL revoking certificate number 2
        X509CRL	crl = createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);
        
        // verify the CRL
        crl.verify(caCert.getPublicKey(), "BC");
        
        // check if the CRL revokes certificate number 2
        X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
        System.out.println("Revocation Details:");
        System.out.println("  Certificate number: " + entry.getSerialNumber());
        System.out.println("  Issuer            : " + crl.getIssuerX500Principal());
        
        if (entry.hasExtensions())
        {
            byte[]	ext = entry.getExtensionValue(X509Extensions.ReasonCode.getId());
            
            if (ext != null)
            {
                DEREnumerated	reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(ext);
                
                System.out.println("  Reason Code       : " + reasonCode.getValue());
            }
        }
    }
}
