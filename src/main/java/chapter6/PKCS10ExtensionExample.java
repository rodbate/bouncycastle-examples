package chapter6;

import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Generation of a basic PKCS #10 request with an extension.
 */
public class PKCS10ExtensionExample
{
    public static PKCS10CertificationRequest generateRequest(
        KeyPair pair)
        throws Exception
    {
        // create a SubjectAlternativeName extension value
        GeneralNames  subjectAltNames = new GeneralNames(
                 new GeneralName(GeneralName.rfc822Name, "test@test.test"));

        // create the extensions object and add it as an attribute
        Vector  oids = new Vector();
        Vector	values = new Vector();

        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltNames)));
        
        X509Extensions	extensions = new X509Extensions(oids, values);
        
        Attribute  attribute = new Attribute(
                                 PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, 
                                 new DERSet(extensions));
        
        return new PKCS10CertificationRequest(
                "SHA256withRSA",
                new X500Principal("CN=Requested Test Certificate"),
                pair.getPublic(),
                new DERSet(attribute),
                pair.getPrivate());
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        // create the keys
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        kpGen.initialize(1024, Utils.createFixedRandom());
        
        KeyPair          pair = kpGen.generateKeyPair();
        
        PKCS10CertificationRequest  request = generateRequest(pair);
        
        PEMWriter        pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
        
        pemWrt.writeObject(request);
        
        pemWrt.close();
    }
}