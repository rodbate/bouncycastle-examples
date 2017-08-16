package chapter7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.ocsp.*;

/**
 * Example of OCSP response generation.
 */
public class OCSPResponderExample
{
    /*public static OCSPResp generateOCSPResponse(OCSPReq request, PrivateKey responderKey, PublicKey pubKey, CertificateID revokedID)
        throws NoSuchProviderException, OCSPException
    {
        BasicOCSPRespGenerator basicRespGen = new BasicOCSPRespGenerator(pubKey);
        
        X509Extensions         reqExtensions = request.getRequestExtensions();
        
        if (reqExtensions != null)
        {
            X509Extension      ext = reqExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        
            if (ext != null)
            {
                Vector oids = new Vector();
                Vector values = new Vector();
                
                oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                values.add(ext);
                
                basicRespGen.setResponseExtensions(new X509Extensions(oids, values));
            }
        }
        
        Req[] requests = request.getRequestList();
        
        for (int i = 0; i != requests.length; i++)
        {
            CertificateID certID = requests[i].getCertID();
            
            // this would normally be a lot more general!
            if (certID.equals(revokedID))
            {
                basicRespGen.addResponse(certID, new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn));
            }
            else
            {
                basicRespGen.addResponse(certID, CertificateStatus.GOOD);
            }
        }

        BasicOCSPResp          basicResp = basicRespGen.generate("SHA256WithRSA", responderKey, null, new Date(), "BC");
        
        OCSPRespGenerator      respGen = new OCSPRespGenerator();
        
        return respGen.generate(OCSPRespGenerator.SUCCESSFUL, basicResp);
    }
    
    public static String getStatusMessage(KeyPair responderPair, X509Certificate caCert, BigInteger revokedSerialNumber, X509Certificate cert)
        throws Exception
    {
        OCSPReq request = OCSPClientExample.generateOCSPRequest(caCert, cert.getSerialNumber());

        CertificateID revokedID = new CertificateID(CertificateID.HASH_SHA1, caCert, revokedSerialNumber);
        OCSPResp response = generateOCSPResponse(request, responderPair.getPrivate(), responderPair.getPublic(), revokedID);
        
        BasicOCSPResp   basicResponse = (BasicOCSPResp)response.getResponseObject();
        
        // verify the response
        if (basicResponse.verify(responderPair.getPublic(), "BC"))
        {
            SingleResp[]      responses = basicResponse.getResponses();
            
            byte[] reqNonce = request.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
            byte[] respNonce = basicResponse.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

            // validate the nonce if it is present
            if (reqNonce == null || Arrays.equals(reqNonce, respNonce))
            {
                String message = "";
	            for (int i = 0; i != responses.length; i++)
	            {
	                message += " certificate number " + responses[i].getCertID().getSerialNumber();
	                if (responses[i].getCertStatus() == CertificateStatus.GOOD)
	                {
	                    return message + " status: good";
	                }
	                else
	                {
	                    return message + " status: revoked";
	                }
	            }
	            
	            return message;
            }
            else
            {
                return "response nonce failed to validate";
            }
        }
        else
        {
            return "response failed to verify";
        }
    }
    
    public static void main(
        String[] args)
        throws Exception
    {
        KeyPair         rootPair = Utils.generateRSAKeyPair();
        KeyPair         interPair = Utils.generateRSAKeyPair();
        
        X509Certificate rootCert = Utils.generateRootCert(rootPair);
        X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);

        System.out.println(getStatusMessage(rootPair, rootCert, BigInteger.valueOf(1), interCert));
    }*/
}