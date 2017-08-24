package chapter4;

import rb.BaseClass;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

/**
 * Diffie-Hellman using Elliptic Curve cryptography.
 */
public class BasicECDHExample extends BaseClass {
    public static void main(
        String[]    args)
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve    curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), // p
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

        ECParameterSpec  ecSpec = new ECParameterSpec(
                curve,
                new ECPoint(
                        new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                        new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16)), // G
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16), // order
                1); // h

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
