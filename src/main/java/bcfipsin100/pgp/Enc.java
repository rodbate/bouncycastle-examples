package bcfipsin100.pgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;

import bcfipsin100.base.EC;
import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import bcfipsin100.util.ExValues;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class Enc
{
    public static byte[] createRsaEncryptedObject(PGPPublicKey encryptionKey, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(bOut,
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            data.length,
            new Date());
        pOut.write(data);
        pOut.close();

        byte[] plainText = bOut.toByteArray();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BCFIPS"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BCFIPS"));

        OutputStream cOut = encGen.open(encOut, plainText.length);

        cOut.write(plainText);

        cOut.close();

        return encOut.toByteArray();
    }

    public static byte[] extractRsaEncryptedObject(PGPPrivateKey privateKey, byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);

        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BCFIPS").build(privateKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);

        byte[] literalData = Streams.readAll(clear);

        if (encData.verify())
        {
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();

            byte[] data = Streams.readAll(litData.getInputStream());

            return data;
        }

        throw new IllegalStateException("modification check failed");
    }

    public static byte[] createKeyAgreeEncryptedObject(PGPPublicKey recipientKey, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(bOut,
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            data.length,
            new Date());
        pOut.write(data);
        pOut.close();

        byte[] plainText = bOut.toByteArray();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BCFIPS"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(recipientKey).setProvider("BCFIPS"));

        OutputStream cOut = encGen.open(encOut, plainText.length);

        cOut.write(plainText);

        cOut.close();

        return encOut.toByteArray();
    }

    public static byte[] extractKeyAgreeEncryptedObject(PGPPrivateKey recipientPrivateKey, byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);

        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BCFIPS").build(recipientPrivateKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);

        byte[] literalData = Streams.readAll(clear);

        if (encData.verify())
        {
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();

            byte[] data = Streams.readAll(litData.getInputStream());

            return data;
        }

        throw new IllegalStateException("modification check failed");
    }

    public static byte[] createPbeEncryptedObject(char[] passwd, byte[] data)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(bOut,
            PGPLiteralData.BINARY,
            PGPLiteralData.CONSOLE,
            data.length,
            new Date());
        pOut.write(data);
        pOut.close();

        byte[] plainText = bOut.toByteArray();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BCFIPS"));

        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passwd).setProvider("BCFIPS"));

        OutputStream cOut = encGen.open(encOut, plainText.length);

        cOut.write(plainText);

        cOut.close();

        return encOut.toByteArray();
    }

    public static byte[] extractPbeEncryptedObject(char[] passwd, byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

        PGPPBEEncryptedData encData = (PGPPBEEncryptedData)encList.get(0);

        PBEDataDecryptorFactory dataDecryptorFactory = new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BCFIPS").build()).setProvider("BCFIPS").build(passwd);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);

        byte[] literalData = Streams.readAll(clear);

        if (encData.verify())
        {
            PGPObjectFactory litFact = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData)litFact.nextObject();

            byte[] data = Streams.readAll(litData.getInputStream());

            return data;
        }

        throw new IllegalStateException("modification check failed");
    }

    public static byte[] createSignedEncryptedObject(PGPPublicKey encryptionKey, PGPPrivateKey signingKey, byte[] data)
        throws PGPException, IOException
    {
        byte[] plainText = Sign.createSignedObject(PublicKeyAlgorithmTags.ECDSA, signingKey, data);

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom())
                .setProvider("BCFIPS"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BCFIPS"));

        OutputStream cOut = encGen.open(encOut, plainText.length);

        cOut.write(plainText);

        cOut.close();

        return encOut.toByteArray();
    }

    public static boolean verifySignedEncryptedObject(PGPPrivateKey decryptionKey, PGPPublicKey verificationKey, byte[] pgpEncryptedData)
        throws PGPException, IOException
    {
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpEncryptedData);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();

        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);

        PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BCFIPS").build(decryptionKey);

        InputStream clear = encData.getDataStream(dataDecryptorFactory);

        byte[] signedData = Streams.readAll(clear);

        if (encData.verify())
        {
            return Sign.verifySignedObject(verificationKey, signedData);
        }

        throw new IllegalStateException("modification check failed");
    }

    public static void main(String[] args)
        throws GeneralSecurityException, OperatorCreationException, PGPException, IOException
    {
        Setup.installProvider();

        KeyPair ecKeyPair = EC.generateKeyPair();
        KeyPair ecSigningKeyPair = EC.generateKeyPair();
        KeyPair rsaKeyPair = Rsa.generateKeyPair();

        PGPKeyPair ecPgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, ecKeyPair, new Date());
        PGPKeyPair ecPgpSigningKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, ecSigningKeyPair, new Date());
        PGPKeyPair rsaPgpKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_ENCRYPT, rsaKeyPair, new Date());

        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractRsaEncryptedObject(rsaPgpKeyPair.getPrivateKey(), createRsaEncryptedObject(rsaPgpKeyPair.getPublicKey(), ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractKeyAgreeEncryptedObject(ecPgpKeyPair.getPrivateKey(), createKeyAgreeEncryptedObject(ecPgpKeyPair.getPublicKey(), ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, extractPbeEncryptedObject("password".toCharArray(), createPbeEncryptedObject("password".toCharArray(), ExValues.SampleInput))));
        System.err.println(verifySignedEncryptedObject(ecPgpKeyPair.getPrivateKey(), ecPgpSigningKeyPair.getPublicKey(), createSignedEncryptedObject(ecPgpKeyPair.getPublicKey(), ecPgpSigningKeyPair.getPrivateKey(), ExValues.SampleInput)));
    }
}
