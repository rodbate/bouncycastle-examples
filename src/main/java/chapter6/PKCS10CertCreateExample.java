package chapter6;

import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 * An example of a basic CA.
 */
public class PKCS10CertCreateExample
{
    /*public static X509Certificate[] buildChain()
        throws Exception
    {
        // create the certification request
        KeyPair          pair = Utils.generateRSAKeyPair();
        
        PKCS10CertificationRequest  request = PKCS10ExtensionExample.generateRequest(pair);
        
        // create a root certificate
        KeyPair          rootPair = Utils.generateRSAKeyPair();
        X509Certificate  rootCert = X509V1CreateExample.generateV1Certificate(rootPair);
        
        // validate the certification request
        if (!request.verify("BC"))
        {
            System.out.println("request failed to verify!");
            System.exit(1);
        }
        
        // create the certificate using the information in the request
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(rootCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
        certGen.setPublicKey(request.getPublicKey("BC"));
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert));
        
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));
        
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        
        // extract the extension request attribute
        ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();
        
        for (int i = 0; i != attributes.size(); i++)
        {
            Attribute    attr = Attribute.getInstance(attributes.getObjectAt(i));
            
            // process extension request
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest))
            {
                X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                
                Enumeration e = extensions.oids();
                while (e.hasMoreElements())
                {
                    DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
                    X509Extension       ext = extensions.getExtension(oid);
                    
                    certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
                }
            }
        }
        
        X509Certificate  issuedCert = certGen.generateX509Certificate(rootPair.getPrivate());
        
        return new X509Certificate[] { issuedCert, rootCert };
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {    
        X509Certificate[]    chain = buildChain();
        
        PEMWriter        pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
        
        pemWrt.writeObject(chain[0]);
        pemWrt.writeObject(chain[1]);
        
        pemWrt.close();
    }*/
}