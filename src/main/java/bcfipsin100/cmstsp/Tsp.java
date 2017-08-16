package bcfipsin100.cmstsp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

public class Tsp
{
    public static byte[] createTspRequest(byte[] sha384Data)
        throws IOException
    {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
                  reqGen.setCertReq(true);
        return reqGen.generate(TSPAlgorithms.SHA384, sha384Data).getEncoded();
    }

    public static byte[] createTspResponse(PrivateKey tspSigningKey, X509Certificate tspSigningCert, byte[] encRequest)
        throws TSPException, OperatorCreationException, GeneralSecurityException, IOException
    {
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        DigestCalculatorProvider digProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().build("SHA384withRSA", tspSigningKey, tspSigningCert),
                digProvider.get(digestAlgorithm),
                new ASN1ObjectIdentifier("1.2"));

        tsTokenGen.addCertificates(new JcaCertStore(Collections.singleton(tspSigningCert)));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        return tsRespGen.generate(new TimeStampRequest(encRequest), new BigInteger("23"), new Date()).getEncoded();
    }

    public static boolean verifyTspResponse(X509Certificate tspCertificate, byte[] encResponse)
        throws IOException, TSPException, OperatorCreationException
    {
        TimeStampResponse tsResp = new TimeStampResponse(encResponse);

        TimeStampToken tsToken = tsResp.getTimeStampToken();

        tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BCFIPS").build(tspCertificate));

        return true;
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, TSPException, IOException
    {
        Setup.installProvider();

        KeyPair rsaTspCaSigningKeyPair = Rsa.generateKeyPair();
        KeyPair rsaTspSigningKeyPair = Rsa.generateKeyPair();

        X509Certificate rsaCaCert = Cert.makeV1RsaCertificate(rsaTspCaSigningKeyPair.getPrivate(), rsaTspCaSigningKeyPair.getPublic());
        X509Certificate rsaSigningCert = Cert.makeRsaTspCertificate(rsaCaCert, rsaTspCaSigningKeyPair.getPrivate(), rsaTspSigningKeyPair.getPublic());

        System.err.println(verifyTspResponse(rsaSigningCert, createTspResponse(rsaTspSigningKeyPair.getPrivate(), rsaSigningCert, createTspRequest(new byte[48]))));
    }
}
