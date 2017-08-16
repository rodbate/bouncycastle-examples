package bcfipsin100.pbeks;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import bcfipsin100.base.Rsa;
import bcfipsin100.base.Setup;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

public class Key
{
    public static byte[] encodePublic(PublicKey publicKey)
    {
        return publicKey.getEncoded();
    }

    public static PublicKey producePublicKey(byte[] encoding)
        throws GeneralSecurityException
    {
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BCFIPS");

        return keyFact.generatePublic(new X509EncodedKeySpec(encoding));
    }

    public static byte[] encodePrivate(PrivateKey privateKey)
    {
        return privateKey.getEncoded();
    }

    public static PrivateKey producePrivateKey(byte[] encoding)
        throws GeneralSecurityException
    {
        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BCFIPS");

        return keyFact.generatePrivate(new PKCS8EncodedKeySpec(encoding));
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException
    {
        Setup.installProvider();

        KeyPair keyPair = Rsa.generateKeyPair();

        System.err.println(keyPair.getPublic().equals(producePublicKey(encodePublic(keyPair.getPublic()))));
        System.err.println(keyPair.getPrivate().equals(producePrivateKey(encodePrivate(keyPair.getPrivate()))));
    }
}
