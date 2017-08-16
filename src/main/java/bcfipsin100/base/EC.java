package bcfipsin100.base;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import bcfipsin100.util.ExValues;
import org.bouncycastle.crypto.util.DERMacData;
import org.bouncycastle.jcajce.AgreedKeyWithMacKey;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


public class EC
{
    public static KeyPair generateKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");

        keyPair.initialize(1024);

        return keyPair.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey ecPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initSign(ecPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifySignature(PublicKey ecPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");

        signature.initVerify(ecPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static KeyPair generateKeyPairUsingCurveName(String curveName)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BCFIPS");

        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }

    public static byte[] initiatorAgreementBasic(PrivateKey initiatorPrivate, PublicKey recipientPublic)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDH", "BCFIPS");

        agreement.init(initiatorPrivate);

        agreement.doPhase(recipientPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] recipientAgreementBasic(PrivateKey recipientPrivate, PublicKey initiatorPublic)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDH", "BCFIPS");

        agreement.init(recipientPrivate);

        agreement.doPhase(initiatorPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] initiatorAgreementWithKdf(PrivateKey initiatorPrivate, PublicKey recipientPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BCFIPS");

        agreement.init(initiatorPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(recipientPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[] recipientAgreementWithKdf(PrivateKey recipientPrivate, PublicKey initiatorPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BCFIPS");

        agreement.init(recipientPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(initiatorPublic, true);

        SecretKey agreedKey = agreement.generateSecret("AES[256]");

        return agreedKey.getEncoded();
    }

    public static byte[][] initiatorAgreeKeyEstablishWithKeyConfirmation(PrivateKey initiatorPrivate, PublicKey recipientPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BCFIPS");

        agreement.init(initiatorPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(recipientPublic, true);

        AgreedKeyWithMacKey agreedKey = (AgreedKeyWithMacKey)agreement.generateSecret("CMAC[128]" + "/" + "AES[256]");

        Mac mac = Mac.getInstance("CMAC", "BCFIPS");

        mac.init(agreedKey.getMacKey());

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, null).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        agreedKey.getMacKey().zeroize();

        return new byte[][] { agreedKey.getEncoded(), encMac };
    }

    public static byte[][] recipientAgreeKeyEstablishWithKeyConfirmation(PrivateKey recipientPrivate, PublicKey initiatorPublic, byte[] userKeyingMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("ECCDHwithSHA384CKDF", "BCFIPS");

        agreement.init(recipientPrivate, new UserKeyingMaterialSpec(userKeyingMaterial));

        agreement.doPhase(initiatorPublic, true);

        AgreedKeyWithMacKey agreedKey = (AgreedKeyWithMacKey)agreement.generateSecret("CMAC[128]" + "/" + "AES[256]");

        Mac mac = Mac.getInstance("CMAC", "BCFIPS");

        mac.init(agreedKey.getMacKey());

        DERMacData macData = new DERMacData.Builder(DERMacData.Type.UNILATERALU,
            ExValues.Initiator, ExValues.Recipient, null, null).build();

        byte[] encMac = mac.doFinal(macData.getMacData());

        agreedKey.getMacKey().zeroize();

        return new byte[][] { agreedKey.getEncoded(), encMac };
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException
    {
        Setup.installProvider();

        KeyPair signingPair384 = generateKeyPair();

        byte[] dsaSignature = generateSignature(signingPair384.getPrivate(), ExValues.SampleInput);

        System.err.println("ECDSA verified: " + verifySignature(signingPair384.getPublic(), ExValues.SampleInput, dsaSignature));

        KeyPair signingPair256 = generateKeyPairUsingCurveName("P-256");

        dsaSignature = generateSignature(signingPair256.getPrivate(), ExValues.SampleInput);

        System.err.println("ECDSA (with curve name) verified: " + verifySignature(signingPair256.getPublic(), ExValues.SampleInput, dsaSignature));

        KeyPair initiatorPair = generateKeyPair();
        KeyPair recipientPair = generateKeyPair();

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
