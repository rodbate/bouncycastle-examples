package bcfipsin100.base;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import bcfipsin100.util.ExValues;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.util.DERMacData;
import org.bouncycastle.jcajce.KTSKeyWithEncapsulation;
import org.bouncycastle.jcajce.ZeroizableSecretKey;
import org.bouncycastle.jcajce.spec.KTSExtractKeySpec;
import org.bouncycastle.jcajce.spec.KTSGenerateKeySpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Rsa
{
    public static KeyPair generateKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");

        keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));

        return keyPair.generateKeyPair();
    }

    public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static byte[] generateX931Signature(PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA/X9.31", "BCFIPS");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifyX931Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA/X9.31", "BCFIPS");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static byte[] generatePssSignature(PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSAandMGF1", "BCFIPS");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifyPssSignature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSAandMGF1", "BCFIPS");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static byte[][] generatePssSignatureWithParameters(PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException, IOException
    {
        Signature signature = Signature.getInstance("SHA384withRSAandMGF1", "BCFIPS");

        signature.setParameter(new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 0, PSSParameterSpec.DEFAULT.getTrailerField()));
        signature.initSign(rsaPrivate);

        signature.update(input);

        AlgorithmParameters pssParameters = signature.getParameters();

        return new byte[][] { signature.sign(), pssParameters.getEncoded() };
    }

    public static boolean verifyPssSignatureWithParameters(PublicKey rsaPublic, byte[] input, byte[] encSignature, byte[] encParameters)
        throws GeneralSecurityException, IOException
    {
        AlgorithmParameters pssParameters = AlgorithmParameters.getInstance("PSS", "BCFIPS");

        pssParameters.init(encParameters);

        PSSParameterSpec pssParameterSpec = pssParameters.getParameterSpec(PSSParameterSpec.class);

        Signature signature = Signature.getInstance("SHA384withRSAandMGF1", "BCFIPS");

        signature.setParameter(pssParameterSpec);

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static byte[] oaepKeyWrap(PublicKey rsaPublic, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BCFIPS");

        c.init(Cipher.WRAP_MODE, rsaPublic);

        return c.wrap(secretKey);
    }

    public static Key oaepKeyUnwrap(PrivateKey rsaPrivate, byte[] wrappedKey)
        throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BCFIPS");

        c.init(Cipher.UNWRAP_MODE, rsaPrivate);

        return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static byte[][] oaepKeyWrapWithParameters(PublicKey rsaPublic, SecretKey secretKey)
        throws GeneralSecurityException, IOException
    {
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BCFIPS");

        c.init(Cipher.WRAP_MODE, rsaPublic, new OAEPParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), PSource.PSpecified.DEFAULT));

        return new byte[][] { c.wrap(secretKey), c.getParameters().getEncoded() };
    }

    public static Key oaepKeyUnwrapWithParameters(PrivateKey rsaPrivate, byte[] wrappedKey, byte[] encParameters)
        throws GeneralSecurityException, IOException
    {
        Cipher c = Cipher.getInstance("RSA/NONE/OAEPPadding", "BCFIPS");

        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("OAEP", "BCFIPS");

        algorithmParameters.init(encParameters);

        c.init(Cipher.UNWRAP_MODE, rsaPrivate, algorithmParameters);

        return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static byte[] kemKeyWrap(PublicKey rsaPublic, SecretKey secretKey)
        throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        c.init(Cipher.WRAP_MODE, rsaPublic, new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(), 256).build());

        return c.wrap(secretKey);
    }

    public static Key kemKeyUnwrap(PrivateKey rsaPrivate, byte[] wrappedKey)
        throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        c.init(Cipher.UNWRAP_MODE, rsaPrivate, new KTSParameterSpec.Builder(NISTObjectIdentifiers.id_aes256_wrap.getId(), 256).build());

        return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static byte[][] initiatorOaepKeyEstablishWithKeyConfirmation(PublicKey rsaPublic)
        throws GeneralSecurityException
    {
        SecretKeyFactory kemFact = SecretKeyFactory.getInstance("RSA-KTS-OAEP", "BCFIPS");

        KTSGenerateKeySpec kemParams = new KTSGenerateKeySpec.Builder(rsaPublic, "AES", 256).withMac("HmacSHA384", 384).build();

        KTSKeyWithEncapsulation encapsKey = (KTSKeyWithEncapsulation)kemFact.generateSecret(kemParams);

        ZeroizableSecretKey macKey = encapsKey.getMacKey();

        Mac mac = Mac.getInstance(macKey.getAlgorithm(), "BCFIPS");

        mac.init(macKey);

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, encapsKey.getEncapsulation()).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        macKey.zeroize();

        return new byte[][] { encapsKey.getEncoded(), encapsKey.getEncapsulation(), encMac };
    }

    public static byte[][] recipientOaepKeyEstablishWithKeyConfirmation(PrivateKey rsaPrivate, byte[] encapsulation)
        throws GeneralSecurityException
    {
        SecretKeyFactory kemFact = SecretKeyFactory.getInstance("RSA-KTS-OAEP", "BCFIPS");

        KTSExtractKeySpec kemParams = new KTSExtractKeySpec.Builder(rsaPrivate, encapsulation, "AES", 256).withMac("HmacSHA384", 384).build();

        KTSKeyWithEncapsulation encapsKey = (KTSKeyWithEncapsulation)kemFact.generateSecret(kemParams);

        ZeroizableSecretKey macKey = encapsKey.getMacKey();

        Mac mac = Mac.getInstance(macKey.getAlgorithm(), "BCFIPS");

        mac.init(macKey);

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, encapsKey.getEncapsulation()).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        macKey.zeroize();

        return new byte[][] { encapsKey.getEncoded(), encapsKey.getEncapsulation(), encMac };
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException
    {
        Setup.installProvider();

        KeyPair signingPair = generateKeyPair();

        byte[] pkcs1Signature = generatePkcs1Signature(signingPair.getPrivate(), ExValues.SampleInput);

        System.err.println("PKCS#1.5 verified: " + verifyPkcs1Signature(signingPair.getPublic(), ExValues.SampleInput, pkcs1Signature));

        byte[] x931Signature = generateX931Signature(signingPair.getPrivate(), ExValues.SampleInput);

        System.err.println("X9.31 verified: " + verifyX931Signature(signingPair.getPublic(), ExValues.SampleInput, x931Signature));

        byte[] pssSignature = generatePssSignature(signingPair.getPrivate(), ExValues.SampleInput);

        System.err.println("PSS verified: " + verifyPssSignature(signingPair.getPublic(), ExValues.SampleInput, pssSignature));

        byte[][] sigAndParam = generatePssSignatureWithParameters(signingPair.getPrivate(), ExValues.SampleInput);

        System.err.println("PSS (with parameters) verified: " + verifyPssSignatureWithParameters(signingPair.getPublic(), ExValues.SampleInput, sigAndParam[0], sigAndParam[1]));

        KeyPair encryptionPair = generateKeyPair();

        byte[] kemWrap = kemKeyWrap(encryptionPair.getPublic(), ExValues.SampleAesKey);

        Key key = kemKeyUnwrap(encryptionPair.getPrivate(), kemWrap);

        System.err.println("KEM key: " + Arrays.areEqual(key.getEncoded(), ExValues.SampleAesKey.getEncoded()) + ", " + Hex.toHexString(key.getEncoded()));

        byte[] oaepWrap = oaepKeyWrap(encryptionPair.getPublic(), ExValues.SampleAesKey);

        Key oaepKey = oaepKeyUnwrap(encryptionPair.getPrivate(), oaepWrap);

        System.err.println("OAEP key: " + Arrays.areEqual(oaepKey.getEncoded(), ExValues.SampleAesKey.getEncoded()) + ", " + Hex.toHexString(oaepKey.getEncoded()));

        byte[][] oaepWrapWithParams = oaepKeyWrapWithParameters(encryptionPair.getPublic(), ExValues.SampleAesKey);

        Key oaepWithParamsKey = oaepKeyUnwrapWithParameters(encryptionPair.getPrivate(), oaepWrapWithParams[0], oaepWrapWithParams[1]);

        System.err.println("OAEP (with parameters) key: " + Arrays.areEqual(oaepWithParamsKey.getEncoded(), ExValues.SampleAesKey.getEncoded()) + ", " + Hex.toHexString(oaepWithParamsKey.getEncoded()));

        byte[][] oaepInitKeyEncMac = initiatorOaepKeyEstablishWithKeyConfirmation(encryptionPair.getPublic());

        byte[][] oaepRecipKeyEncMac = recipientOaepKeyEstablishWithKeyConfirmation(encryptionPair.getPrivate(), oaepInitKeyEncMac[1]);

        System.err.println("OAEP (with key confirmation) key: " + Arrays.areEqual(oaepInitKeyEncMac[0], oaepRecipKeyEncMac[0]) + ", " + Arrays.areEqual(oaepInitKeyEncMac[2], oaepRecipKeyEncMac[2]) + ", "+ Hex.toHexString(oaepInitKeyEncMac[0]));
    }
}
