package chapter7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;

/**
 * Example of unsigned OCSP request generation.
 */
public class OCSPClientExample
{
    public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
        throws OCSPException
    {
        // Generate the id for the certificate we are looking for
        /*CertificateID   id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);

        // basic request generation with nonce
        OCSPReqGenerator    gen = new OCSPReqGenerator();
        
        gen.addRequest(id);
        
        // create details for nonce extension
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Vector     oids = new Vector();
        Vector     values = new Vector();
        
        oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
        
        gen.setRequestExtensions(new X509Extensions(oids, values));

        return gen.generate();*/
        return null;
    }

    public static void main(
        String[] args)
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = Utils.generateRSAKeyPair();
        KeyPair         interPair = Utils.generateRSAKeyPair();
        
        X509Certificate rootCert = Utils.generateRootCert(rootPair);
        X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);

        OCSPReq request = generateOCSPRequest(rootCert, interCert.getSerialNumber());

        Req[]   requests = request.getRequestList();
        
        for (int i = 0; i != requests.length; i++)
        {
            CertificateID certID = requests[i].getCertID();
            
            System.out.println("OCSP Request to check certificate number " + certID.getSerialNumber());
        }
    }
}
