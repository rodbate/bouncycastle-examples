package chapter4;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

public class NamedCurveExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        KeyPairGenerator   keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        
        keyGen.initialize(ecSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();
        
        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest	hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());
        
        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }
}
