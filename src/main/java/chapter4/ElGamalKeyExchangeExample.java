package chapter4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * RSA example with OAEP Padding and random key generation.
 */
public class ElGamalKeyExchangeExample
{
    private static byte[] packKeyAndIv(
        Key	            key,
        IvParameterSpec ivSpec)
        throws IOException
    {
        ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
        
        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());
        
        return bOut.toByteArray();
    }
    
    private static Object[] unpackKeyAndIV(
        byte[]    data)
    {
        byte[]    keyD = new byte[16];
        byte[]    iv = new byte[data.length - 16];
        
        return new Object[] {
             new SecretKeySpec(data, 16, data.length - 16, "AES"),
             new IvParameterSpec(data, 0, 16)
        };
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        SecureRandom     random = new SecureRandom();
        
        // create the El Gamal Key
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ELGamal", "BC");
        
        generator.initialize(512, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input            : " + Utils.toHex(input));
        
        // create the symmetric key and iv
        Key             sKey = Utils.createKeyForAES(256, random);
        IvParameterSpec sIvSpec = Utils.createCtrIvForAES(0, random);
        
        // symmetric key/iv wrapping step
        Cipher	        xCipher = Cipher.getInstance("ElGamal/None/PKCS1Padding", "BC");
        
        xCipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        
        byte[]          keyBlock = xCipher.doFinal(packKeyAndIv(sKey, sIvSpec));
        
        // encryption step
        Cipher          sCipher	= Cipher.getInstance("AES/CTR/NoPadding", "BC");	
        
        sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);

        byte[] cipherText = sCipher.doFinal(input);

        System.out.println("keyBlock length  : " + keyBlock.length);
        System.out.println("cipherText length: " + cipherText.length);
        
        // symmetric key/iv unwrapping step
        xCipher.init(Cipher.DECRYPT_MODE, privKey);
        
        Object[]	keyIv = unpackKeyAndIV(xCipher.doFinal(keyBlock));
        
        // decryption step
        sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);

        byte[] plainText = sCipher.doFinal(cipherText);
        
        System.out.println("plain            : " + Utils.toHex(plainText));
    }
}