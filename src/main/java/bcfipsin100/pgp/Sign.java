package bcfipsin100.pgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Date;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.util.ExValues;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.operator.OperatorCreationException;

public class Sign
{
    public static byte[] createSignedObject(int signingAlg, PGPPrivateKey signingKey, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA384).setProvider("BCFIPS"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        BCPGOutputStream bcOut = new BCPGOutputStream(bOut);

        sGen.generateOnePassVersion(false).encode(bcOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        OutputStream lOut = lGen.open(
            bcOut,
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.length,
            new Date());

        for (int i = 0; i != data.length; i++)
        {
            lOut.write(data[i]);
            sGen.update(data[i]);
        }

        lGen.close();

        sGen.generate().encode(bcOut);

        return bOut.toByteArray();
    }

    public static boolean verifySignedObject(PGPPublicKey verifyingKey, byte[] pgpSignedData)
        throws PGPException, IOException
    {
        JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(pgpSignedData);

        PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = onePassList.get(0);

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();

        InputStream dIn = literalData.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BCFIPS"), verifyingKey);

        int ch;
        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }

    public static byte[] createDetachedSignature(int signingAlg, PGPPrivateKey signingKey, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA384).setProvider("BCFIPS"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, signingKey);

        for (int i = 0; i != data.length; i++)
        {
            sGen.update(data[i]);
        }

        sGen.generate().encode(bOut);

        return bOut.toByteArray();
    }

    public static boolean verifyDetachedSignature(PGPPublicKey verifyingKey, byte[] pgpSignature, byte[] data)
        throws PGPException, IOException
    {
        JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(pgpSignature);

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BCFIPS"), verifyingKey);

        sig.update(data);

        return sig.verify();
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, PGPException, IOException
    {
        Setup.installProvider();

        KeyPair signKeyPair = EC.generateKeyPair();

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, signKeyPair, new Date());

        System.err.println(verifySignedObject(pgpKeyPair.getPublicKey(), createSignedObject(PublicKeyAlgorithmTags.ECDSA, pgpKeyPair.getPrivateKey(), ExValues.SampleInput)));
        System.err.println(verifyDetachedSignature(pgpKeyPair.getPublicKey(), createDetachedSignature(PublicKeyAlgorithmTags.ECDSA, pgpKeyPair.getPrivateKey(), ExValues.SampleInput), ExValues.SampleInput));
    }
}
