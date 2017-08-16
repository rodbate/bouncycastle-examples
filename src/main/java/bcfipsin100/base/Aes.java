package bcfipsin100.base;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import bcfipsin100.util.ExValues;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Aes
{
    public static SecretKey generateKey()
        throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");

        keyGenerator.init(256);

        return keyGenerator.generateKey();
    }

    public static SecretKey defineKey(byte[] keyBytes)
    {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)
        {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }

        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] ecbEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data);
    }

    public static byte[] ecbDecrypt(SecretKey key, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(cipherText);
    }

    public static byte[][] cbcEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    public static byte[][] cfbEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    public static byte[] cfbDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    public static byte[][] ctrEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(Hex.decode("000102030405060708090a0b")));

        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    public static byte[] ctrDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    public static Object[] gcmEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("000102030405060708090a0b")));

        return new Object[] { cipher.getParameters(), cipher.doFinal(data), };
    }

    public static byte[] gcmDecrypt(SecretKey key, AlgorithmParameters gcmParameters, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameters);

        return cipher.doFinal(cipherText);
    }

    public static Object[] ccmEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("000102030405060708090a0b")));

        return new Object[] { cipher.getParameters(), cipher.doFinal(data) };
    }

    public static byte[] ccmDecrypt(SecretKey key, AlgorithmParameters ccmParameters, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, ccmParameters);

        return cipher.doFinal(cipherText);
    }

    public static Object[] aeadEncrypt(SecretKey key, byte[] data, byte[] associatedData)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, Hex.decode("000102030405060708090a0b")));

        cipher.updateAAD(associatedData);

        return new Object[] { cipher.getParameters(), cipher.doFinal(data) };
    }

    public static byte[] aeadDecrypt(SecretKey key, AlgorithmParameters ccmParameters, byte[] cipherText, byte[] associatedData)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, ccmParameters);

        cipher.updateAAD(associatedData);

        return cipher.doFinal(cipherText);
    }

    public static byte[][] ctsEncrypt(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/CS3Padding", "BCFIPS");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    public static byte[] ctsDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/CS3Padding", "BCFIPS");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    public static byte[] generateMacCMAC(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance("AESCMAC", "BCFIPS");

        mac.init(key);

        return mac.doFinal(data);
    }

    public static byte[] generateMacGMAC(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance("AESGMAC", "BCFIPS");

        mac.init(key, new IvParameterSpec(Hex.decode("000102030405060708090a0b")));

        return mac.doFinal(data);
    }

    public static byte[] generateMacCCM(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance("AESCCMMAC", "BCFIPS");

        mac.init(key, new IvParameterSpec(Hex.decode("000102030405060708090a0b")));

        return mac.doFinal(data);
    }

    public static byte[] wrapKey(SecretKey key, SecretKey keyToWrap)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AESKW", "BCFIPS");

        cipher.init(Cipher.WRAP_MODE, key);

        return cipher.wrap(keyToWrap);
    }

    public static Key unwrapKey(SecretKey key, byte[] wrappedKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AESKW", "BCFIPS");

        cipher.init(Cipher.UNWRAP_MODE, key);

        return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static byte[] wrapKeyWithPadding(SecretKey key, SecretKey keyToWrap)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AESKWP", "BCFIPS");

        cipher.init(Cipher.WRAP_MODE, key);

        return cipher.wrap(keyToWrap);
    }

    public static Key unwrapKeyWithPadding(SecretKey key, byte[] wrappedKey)
        throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AESKWP", "BCFIPS");

        cipher.init(Cipher.UNWRAP_MODE, key);

        return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        Setup.installProvider();

        defineKey(new byte[128 / 8]);
        defineKey(new byte[192 / 8]);
        defineKey(new byte[256 / 8]);

        SecretKey secKey = generateKey();

        System.err.println(Arrays.areEqual(ExValues.SampleInput, ecbDecrypt(secKey, ecbEncrypt(secKey, ExValues.SampleInput))));

        byte[][] cbcOutput = cbcEncrypt(secKey, ExValues.SampleInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, cbcDecrypt(secKey, cbcOutput[0], cbcOutput[1])));

        byte[][] cfbOutput = cfbEncrypt(secKey, ExValues.SampleInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, cfbDecrypt(secKey, cfbOutput[0], cfbOutput[1])));

        byte[][] ctrOutput = ctrEncrypt(secKey, ExValues.SampleInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, ctrDecrypt(secKey, ctrOutput[0], ctrOutput[1])));

        Object[] gcmOutput = gcmEncrypt(secKey, ExValues.SampleInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, gcmDecrypt(secKey, (AlgorithmParameters)gcmOutput[0], (byte[])gcmOutput[1])));

        Object[] ccmOutput = ccmEncrypt(secKey, ExValues.SampleInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, ccmDecrypt(secKey, (AlgorithmParameters)ccmOutput[0], (byte[])ccmOutput[1])));

        Object[] aeadOutput = aeadEncrypt(secKey, ExValues.SampleInput, ExValues.SampleTwoBlockInput);
        System.err.println(Arrays.areEqual(ExValues.SampleInput, aeadDecrypt(secKey, (AlgorithmParameters)aeadOutput[0], (byte[])aeadOutput[1], ExValues.SampleTwoBlockInput)));

        byte[][] ctsOutput = ctsEncrypt(secKey, ExValues.SampleTwoBlockInput);
        System.err.println(Arrays.areEqual(ExValues.SampleTwoBlockInput, ctsDecrypt(secKey, ctsOutput[0], ctsOutput[1])));

        System.err.println(Arrays.areEqual(ExValues.SampleInput, ecbDecrypt(secKey, ecbEncrypt(secKey, ExValues.SampleInput))));
        System.err.println(Arrays.areEqual(ExValues.SampleInput, ecbDecrypt(secKey, ecbEncrypt(secKey, ExValues.SampleInput))));

        System.err.println(Hex.toHexString(generateMacCMAC(secKey, ExValues.SampleInput)));
        System.err.println(Hex.toHexString(generateMacGMAC(secKey, ExValues.SampleInput)));
        System.err.println(Hex.toHexString(generateMacCCM(secKey, ExValues.SampleInput)));

        System.err.println(Arrays.areEqual(ExValues.SampleAesKey.getEncoded(), unwrapKey(secKey, wrapKey(secKey, ExValues.SampleAesKey)).getEncoded()));
        System.err.println(Arrays.areEqual(ExValues.SampleHMacKey.getEncoded(), unwrapKeyWithPadding(secKey, wrapKeyWithPadding(secKey, ExValues.SampleHMacKey)).getEncoded()));
    }
}
