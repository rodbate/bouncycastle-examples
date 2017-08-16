package bcfipsin100.base;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.DSAParameterSpec;

import bcfipsin100.util.ExValues;
import org.bouncycastle.jcajce.spec.DSADomainParametersGenerationParameterSpec;


public class Dsa
{
    public static KeyPair generateKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BCFIPS");

        keyPair.initialize(3072);

        return keyPair.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey dsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withDSA", "BCFIPS");

        signature.initSign(dsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifySignature(PublicKey dsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withDSA", "BCFIPS");

        signature.initVerify(dsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    public static DSAParameterSpec generateParameters()
        throws GeneralSecurityException
    {
        AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DSA", "BCFIPS");

        algGen.init(new DSADomainParametersGenerationParameterSpec(3072, 256, 112));

        AlgorithmParameters dsaParams = algGen.generateParameters();

        return dsaParams.getParameterSpec(DSAParameterSpec.class);
    }

    public static KeyPair generateKeyPairUsingParameters(DSAParameterSpec dsaParameterSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BCFIPS");

        keyPair.initialize(dsaParameterSpec);

        return keyPair.generateKeyPair();
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException
    {
        Setup.installProvider();

        KeyPair signingPair3072 = generateKeyPair();

        byte[] dsaSignature = generateSignature(signingPair3072.getPrivate(), ExValues.SampleInput);

        System.err.println("DSA verified: " + verifySignature(signingPair3072.getPublic(), ExValues.SampleInput, dsaSignature));

        DSAParameterSpec dsaParams = generateParameters();

        System.err.println("DSA parameters: " + dsaParams.getP().toString(16));
        System.err.println("                " + dsaParams.getQ().toString(16));
        System.err.println("                " + dsaParams.getG().toString(16));

        KeyPair signingPairGen3072 = generateKeyPairUsingParameters(dsaParams);

        dsaSignature = generateSignature(signingPairGen3072.getPrivate(), ExValues.SampleInput);

        System.err.println("DSA (with parameters) verified: " + verifySignature(signingPairGen3072.getPublic(), ExValues.SampleInput, dsaSignature));

    }
}
