package bcfipsin100.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

public class Crmf
{
    public static byte[] createCertificateRequestMessage(KeyPair keyPair)
        throws IOException, OperatorCreationException, CRMFException
    {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(keyPair.getPublic())
            .setAuthInfoSender(new X500Principal("CN=CRMF Example"))
            .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(keyPair.getPrivate()));

        return certReqBuild.build().getEncoded();
    }

    public static boolean isValidCertificateRequestMessage(byte[] msgEncoding, PublicKey publicKey)
        throws OperatorCreationException, CRMFException
    {
        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(msgEncoding).setProvider("BCFIPS");

        return certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider("BCFIPS").build(publicKey));
    }

    public static byte[] createEncCertificateRequestMessage(KeyPair keyPair)
        throws IOException, OperatorCreationException, CRMFException
    {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(keyPair.getPublic())
            .setAuthInfoSender(new X500Principal("CN=CRMF Example"))
            .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        return certReqBuild.build().getEncoded();
    }

    public static void main(String[] args)
        throws Exception
    {
        Setup.installProvider();

        KeyPair ecKeyPair = EC.generateKeyPair();

        byte[] encCrmfMessage = createCertificateRequestMessage(ecKeyPair);

        System.err.println(isValidCertificateRequestMessage(encCrmfMessage, ecKeyPair.getPublic()));
        System.err.println(new CertificateRequestMessage(createEncCertificateRequestMessage(ecKeyPair)).getProofOfPossessionType() == CertificateRequestMessage.popKeyEncipherment);
    }
}
