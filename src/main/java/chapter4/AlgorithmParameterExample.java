package chapter4;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

/**
 * El Gamal example with random key generation and AlgorithmParameters.
 */
public class AlgorithmParameterExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        
        // create the parameters
        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
        
        a.init(256, random);
        
        AlgorithmParameters 	params = a.generateParameters();
        AlgorithmParameterSpec	dhSpec = params.getParameterSpec(DHParameterSpec.class);
        
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");
        
        generator.initialize(dhSpec, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));
        
        // encryption step
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));
        
        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils.toHex(plainText));
    }
}
