package chapter4;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

/**
 * Three way key agreement using Diffie-Hellman.
 */
public class ThreeWayDHExample
{
    private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    public static void main(
        String[]    args)
        throws Exception
    {
        DHParameterSpec  dhParams = new DHParameterSpec(p512, g512);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(dhParams, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      cPair = keyGen.generateKeyPair();
        
        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());
        cKeyAgree.init(cPair.getPrivate());

        Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);
        Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);
        Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);

        aKeyAgree.doPhase(cb, true);
        bKeyAgree.doPhase(ac, true);
        cKeyAgree.doPhase(ba, true);

        //      generate the key bytes
        MessageDigest	hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());
        byte[] cShared = hash.digest(cKeyAgree.generateSecret());
        
        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
        System.out.println(Utils.toHex(cShared));
    }
}
