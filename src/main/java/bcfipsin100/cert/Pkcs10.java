package bcfipsin100.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Pkcs10
{
    public static PKCS10CertificationRequest createPkcs10Request()
        throws GeneralSecurityException, OperatorCreationException
    {
        KeyPair ecKeyPair = EC.generateKeyPair();

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(ecKeyPair.getPrivate());

        return new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=PKCS10 Example"), ecKeyPair.getPublic()).build(signer);
    }

    public static PKCS10CertificationRequest createPkcs10RequestWithSubjectAltName()
        throws GeneralSecurityException, OperatorCreationException, IOException
    {
        KeyPair ecKeyPair = EC.generateKeyPair();

        ContentSigner signer = new JcaContentSignerBuilder("SHA384withECDSA")
                                     .setProvider("BCFIPS")
                                     .build(ecKeyPair.getPrivate());

        Extension subjectAltName = new Extension(Extension.subjectAlternativeName, false,
                          new DEROctetString(new GeneralNames(new GeneralName(new X500Name("CN=Alt Name")))));

        return new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=PKCS10 Example"), ecKeyPair.getPublic())
                        .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new Extensions(subjectAltName)).build(signer);
    }

    public static boolean verifyPkcs10Request(PKCS10CertificationRequest pkcs10Request)
        throws GeneralSecurityException, OperatorCreationException, PKCSException
    {
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BCFIPS").build(pkcs10Request.getSubjectPublicKeyInfo());

        return pkcs10Request.isSignatureValid(verifierProvider);
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, PKCSException, IOException
    {
        Setup.installProvider();

        PKCS10CertificationRequest request = createPkcs10Request();

        System.err.println(verifyPkcs10Request(request));

        request = createPkcs10RequestWithSubjectAltName();

        System.err.println(verifyPkcs10Request(request));

        Attribute[] attributes = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

        ASN1Encodable[] attrValues = attributes[0].getAttributeValues();
        Extensions requestExtensions = Extensions.getInstance(attrValues[0]);

        System.err.println(GeneralNames.getInstance(requestExtensions.getExtensionParsedValue(Extension.subjectAlternativeName)));
    }
}
