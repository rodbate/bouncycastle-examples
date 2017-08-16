package bcfipsin100.base;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import bcfipsin100.util.ExValues;
import org.bouncycastle.crypto.util.DERMacData;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


public class DH
{
    public static KeyPair generateKeyPair(DHParameterSpec dhParameterSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BCFIPS");

        // there are precomputed parameters for 2048 bit keys
        keyPair.initialize(dhParameterSpec);

        return keyPair.generateKeyPair();
    }

    public static DHParameterSpec generateParameters()
        throws GeneralSecurityException
    {
        AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BCFIPS");

        algGen.init(3072);

        AlgorithmParameters dsaParams = algGen.generateParameters();

        return dsaParams.getParameterSpec(DHParameterSpec.class);
    }

    public static byte[] initiatorAgreementBasic(PrivateKey initiatorPrivate, PublicKey recipientPublic)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BCFIPS");

        agreement.init(initiatorPrivate);

        agreement.doPhase(recipientPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] recipientAgreementBasic(PrivateKey recipientPrivate, PublicKey initiatorPublic)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BCFIPS");

        agreement.init(recipientPrivate);

        agreement.doPhase(initiatorPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] initiatorAgreementWithKdf(PrivateKey initiatorPrivate, PublicKey recipientPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DHwithSHA384CKDF", "BCFIPS");

        agreement.init(initiatorPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(recipientPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] recipientAgreementWithKdf(PrivateKey recipientPrivate, PublicKey initiatorPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DHwithSHA384CKDF", "BCFIPS");

        agreement.init(recipientPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(initiatorPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[][] initiatorAgreeKeyEstablishWithKeyConfirmation(PrivateKey initiatorPrivate, PublicKey recipientPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DHwithSHA384CKDF", "BCFIPS");

        agreement.init(initiatorPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(recipientPublic, true);

        /*AgreedKeyWithMacKey agreedKey = (AgreedKeyWithMacKey)agreement.generateSecret("CMAC[128]" + "/" + "AES[256]");

        Mac mac = Mac.getInstance("CMAC", "BCFIPS");

        mac.init(agreedKey.getMacKey());

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, null).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        agreedKey.getMacKey().zeroize();

        return new byte[][] { agreedKey.getEncoded(), encMac };*/
        return null;
    }

    public static byte[][] recipientAgreeKeyEstablishWithKeyConfirmation(PrivateKey recipientPrivate, PublicKey initiatorPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DHwithSHA384CKDF", "BCFIPS");

        agreement.init(recipientPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(initiatorPublic, true);

        /*AgreedKeyWithMacKey agreedKey = (AgreedKeyWithMacKey)agreement.generateSecret("CMAC[128]" + "/" + "AES[256]");

        Mac mac = Mac.getInstance("CMAC", "BCFIPS");

        mac.init(agreedKey.getMacKey());

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, null).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        agreedKey.getMacKey().zeroize();

        return new byte[][] { agreedKey.getEncoded(), encMac };*/
        return null;
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException
    {
        Setup.installProvider();

        DHParameterSpec dhParams = generateParameters();

        System.err.println("DH parameters: " + dhParams.getP().toString(16));
        System.err.println("               " + dhParams.getG().toString(16));

        KeyPair initiatorPair = generateKeyPair(dhParams);
        KeyPair recipientPair = generateKeyPair(dhParams);

        byte[] agreeInitKey = initiatorAgreementBasic(initiatorPair.getPrivate(), recipientPair.getPublic());

        byte[] agreeRecipKey = recipientAgreementBasic(recipientPair.getPrivate(), initiatorPair.getPublic());

        System.err.println("Agreement (basic) key: " + Arrays.areEqual(agreeInitKey, agreeRecipKey) + ", " + Hex.toHexString(agreeInitKey));

        byte[] agreeInitWithKdfKey = initiatorAgreementWithKdf(initiatorPair.getPrivate(), recipientPair.getPublic(), ExValues.UKM);

        byte[] agreeRecipWithKdfKey = recipientAgreementWithKdf(recipientPair.getPrivate(), initiatorPair.getPublic(), ExValues.UKM);

        System.err.println("Agreement (with KDF) key: " + Arrays.areEqual(agreeInitWithKdfKey, agreeRecipWithKdfKey) + ", " + Hex.toHexString(agreeInitWithKdfKey));

        byte[][] agreeInitKeyMac = initiatorAgreeKeyEstablishWithKeyConfirmation(initiatorPair.getPrivate(), recipientPair.getPublic(), ExValues.UKM);

        byte[][] agreeRecipKeyMac = recipientAgreeKeyEstablishWithKeyConfirmation(recipientPair.getPrivate(), initiatorPair.getPublic(), ExValues.UKM);

        System.err.println("Agreement (with key confirmation) key: " + Arrays.areEqual(agreeInitKeyMac[0], agreeRecipKeyMac[0]) + ", " + Arrays.areEqual(agreeInitKeyMac[1], agreeRecipKeyMac[1]) + ", "+ Hex.toHexString(agreeInitKeyMac[0]));
    }
}
