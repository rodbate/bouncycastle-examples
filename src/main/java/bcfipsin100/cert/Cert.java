package bcfipsin100.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.util.ExValues;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class Cert
{
    public static X509Certificate makeV1Certificate(PrivateKey caSignerKey, PublicKey caPublicKey)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
            new X500Name("CN=Issuer CA"),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() - 1000L * 5),
            new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
            new X500Name("CN=Issuer CA"),
            caPublicKey);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("SunRsaSign");

        return new JcaX509CertificateConverter().getCertificate(v1CertBldr.build(signerBuilder.build(caSignerKey)));
    }

    public static X509Certificate makeV1RsaCertificate(PrivateKey caSignerKey, PublicKey caPublicKey)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        X509v1CertificateBuilder v1CertBldr = new JcaX509v1CertificateBuilder(
            new X500Name("CN=Issuer CA"),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() - 1000L * 5),
            new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
            new X500Name("CN=Issuer CA"),
            caPublicKey);

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withRSA").setProvider("BCFIPS");

        return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(v1CertBldr.build(signerBuilder.build(caSignerKey)));
    }

    public static X509Certificate makeV3CACertificate(X509Certificate caCertificate, PrivateKey caPrivateKey, PublicKey eePublicKey)
        throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
            caCertificate.getSubjectX500Principal(),
            BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(100)),
            new Date(System.currentTimeMillis() - 1000L * 5),
            new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
            new X500Principal("CN=Cert CA Example"), eePublicKey);

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

        v3CertBldr.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(0));

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS");

        return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

    public static X509Certificate makeV3Certificate(X509Certificate caCertificate, PrivateKey caPrivateKey, PublicKey eePublicKey)
        throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
            caCertificate.getSubjectX500Principal(),
            BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
            new Date(System.currentTimeMillis() - 1000L * 5),
            new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
            new X500Principal("CN=Cert V3 Example"), eePublicKey);

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

        v3CertBldr.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(false));

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS");

        return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

    public static X509Certificate makeRsaTspCertificate(X509Certificate caCertificate, PrivateKey caPrivateKey, PublicKey eePublicKey)
        throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
            caCertificate.getSubjectX500Principal(),
            BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
            new Date(System.currentTimeMillis() - 1000L * 5),
            new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS),
            new X500Principal("CN=Cert V3 Example"), eePublicKey);

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(caCertificate));

        v3CertBldr.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(false));

        v3CertBldr.addExtension(
            Extension.extendedKeyUsage,
            true,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA384withRSA").setProvider("BCFIPS");

        return new JcaX509CertificateConverter().setProvider("BCFIPS").getCertificate(v3CertBldr.build(signerBuilder.build(caPrivateKey)));
    }

    public static X509CRL makeV2Crl(X509Certificate caCert, PrivateKey caPrivateKey, X509Certificate revokedCertificate)
        throws GeneralSecurityException, CertIOException, OperatorCreationException
    {
        Date now = new Date();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), now);

        crlGen.setNextUpdate(new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS));

        if (revokedCertificate != null)
        {
            crlGen.addCRLEntry(revokedCertificate.getSerialNumber(), now, CRLReason.privilegeWithdrawn);
        }

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        X509CRLHolder crl = crlGen.build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(caPrivateKey));

        return new JcaX509CRLConverter().setProvider("BCFIPS").getCRL(crl);
    }

    public static OCSPReq makeOcspRequest(X509Certificate caCert, X509Certificate certToCheck)
        throws OCSPException, OperatorCreationException, CertificateEncodingException
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID certId = new JcaCertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCert, certToCheck.getSerialNumber());

        //
        // basic request generation
        //
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(certId);

        return gen.build();
    }

    public static OCSPResp makeOcspResponse(X509Certificate caCert, PrivateKey caPrivateKey, OCSPReq ocspReq)
        throws OCSPException, OperatorCreationException, CertificateEncodingException
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();
        BasicOCSPRespBuilder respGen = new JcaBasicOCSPRespBuilder(caCert.getPublicKey(), digCalcProv.get(RespID.HASH_SHA1));


        CertificateID certID = ocspReq.getRequestList()[0].getCertID();
        // magic happens...
        respGen.addResponse(certID, CertificateStatus.GOOD);

        BasicOCSPResp resp = respGen.build(
            new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BCFIPS").build(caPrivateKey),
            new X509CertificateHolder[]{new JcaX509CertificateHolder(caCert)},
            new Date());

        OCSPRespBuilder rGen = new OCSPRespBuilder();

        return rGen.build(OCSPRespBuilder.SUCCESSFUL, resp);
    }

    public static boolean isGoodCertificate(OCSPResp ocspResp, X509Certificate caCert, X509Certificate eeCert)
        throws OperatorCreationException, OCSPException, CertificateEncodingException
    {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build();

        if (ocspResp.getStatus() == OCSPRespBuilder.SUCCESSFUL)
        {
            BasicOCSPResp resp = (BasicOCSPResp)ocspResp.getResponseObject();

            if (resp.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCFIPS").build(caCert.getPublicKey())))
            {
                return resp.getResponses()[0].getCertID().matchesIssuer(new JcaX509CertificateHolder(caCert), digCalcProv)
                    && resp.getResponses()[0].getCertID().getSerialNumber().equals(eeCert.getSerialNumber())
                    && resp.getResponses()[0].getCertStatus() == null;
            }
        }

        throw new IllegalStateException("OCSP Request Failed");
    }

    public static PKIXCertPathValidatorResult validateCertPath(X509Certificate taCert, X509Certificate caCert, X509Certificate eeCert)
        throws GeneralSecurityException
    {
        List<X509Certificate> certchain = new ArrayList<X509Certificate>();

        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath certPath = CertificateFactory.getInstance("X.509","BCFIPS").generateCertPath(certchain);

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();

        trust.add(new TrustAnchor(taCert, null));

        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX","BCFIPS");

        PKIXParameters param = new PKIXParameters(trust);

        param.setRevocationEnabled(false);
        param.setDate(new Date());

        return (PKIXCertPathValidatorResult)certPathValidator.validate(certPath, param);
    }

    public static PKIXCertPathValidatorResult validateCertPathWithCrl(X509Certificate taCert, X509CRL taCrl, X509Certificate caCert, X509CRL caCrl, X509Certificate eeCert)
        throws GeneralSecurityException
    {
        List<X509Certificate> certchain = new ArrayList<X509Certificate>();

        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath certPath = CertificateFactory.getInstance("X.509","BCFIPS").generateCertPath(certchain);

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();

        trust.add(new TrustAnchor(taCert, null));

        Set crls = new HashSet();

        crls.add(caCrl);
        crls.add(taCrl);

        CertStore crlsStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls), "BCFIPS");

        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX","BCFIPS");

        PKIXParameters param = new PKIXParameters(trust);

        param.addCertStore(crlsStore);
        param.setDate(new Date());

        return (PKIXCertPathValidatorResult)certPathValidator.validate(certPath, param);
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException
    {
        Setup.installProvider();

        KeyPair taKeyPair = EC.generateKeyPair();
        KeyPair caKeyPair = EC.generateKeyPair();
        KeyPair eeKeyPair = EC.generateKeyPair();

        X509Certificate taCert = makeV1Certificate(taKeyPair.getPrivate(), taKeyPair.getPublic());
        X509Certificate caCert = makeV3CACertificate(taCert, taKeyPair.getPrivate(), caKeyPair.getPublic());
        X509Certificate eeCert = makeV3Certificate(caCert, caKeyPair.getPrivate(), eeKeyPair.getPublic());

        // this will throw an exception in case of failure to verify
        eeCert.verify(caCert.getPublicKey());

        System.err.println("eeCert verified");

        X509CRL taCrl = makeV2Crl(taCert, taKeyPair.getPrivate(), null);

        // this will throw an exception in case of failure to verify
        taCrl.verify(taCert.getPublicKey());

        X509CRL caCrl = makeV2Crl(caCert, caKeyPair.getPrivate(), eeCert);

        caCrl.verify(caCert.getPublicKey());

        System.err.println("caCert CRL verified");

        System.err.println(taCrl.getRevokedCertificate(eeCert));

        OCSPReq ocspReq = makeOcspRequest(taCert, eeCert);

        OCSPResp ocspResp = makeOcspResponse(taCert, taKeyPair.getPrivate(), ocspReq);

        System.err.println(isGoodCertificate(ocspResp, taCert, eeCert));

        System.err.println(validateCertPath(taCert, caCert, eeCert));

        try
        {
            validateCertPathWithCrl(taCert, taCrl, caCert, caCrl, eeCert);

            throw new IllegalStateException("Revocation not picked up!!!");
        }
        catch (CertPathValidatorException e)
        {
            System.err.print("Revoked: " + e.getMessage());
        }
    }
}
