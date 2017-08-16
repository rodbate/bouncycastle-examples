package bcfipsin100.pgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;

import bcfipsin100.base.Dsa;
import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyRing
{
    public static byte[][] generateKeyRing(String identity, char[] passphrase)
        throws GeneralSecurityException, PGPException, IOException
    {
        KeyPair dsaKp = Dsa.generateKeyPair();
        KeyPair rsaKp = Rsa.generateKeyPair();

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair, identity, sha1Calc, null, null,
            new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc)
                .setProvider("BCFIPS").build(passphrase));

        keyRingGen.addSubKey(rsaKeyPair);

        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();

        keyRingGen.generateSecretKeyRing().encode(secretOut);

        secretOut.close();

        ByteArrayOutputStream publicOut = new ByteArrayOutputStream();

        keyRingGen.generatePublicKeyRing().encode(publicOut);

        publicOut.close();

        return new byte[][] { secretOut.toByteArray(), publicOut.toByteArray() };
    }

    public static void main(String[] args)
        throws IOException, GeneralSecurityException, PGPException
    {
        Setup.installProvider();

        byte[][] rings = generateKeyRing("eric@bouncycastle.org", "passphrase".toCharArray());

        System.err.println(new PGPSecretKeyRing(rings[0], new JcaKeyFingerprintCalculator()).getPublicKey().getUserIDs().next());
        System.err.println(new PGPPublicKeyRing(rings[1], new JcaKeyFingerprintCalculator()).getPublicKey().getUserIDs().next());
    }
}
