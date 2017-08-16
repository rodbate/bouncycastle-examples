package chapter3;

import java.security.MessageDigest;

/**
 * A basic implementation of PKCS #5 Scheme 1.
 */
public class PKCS5Scheme1
{
    private MessageDigest digest;
    
    public PKCS5Scheme1(
        MessageDigest    digest)
    {
        this.digest = digest;
    }

    public byte[] generateDerivedKey(
        char[] password,
        byte[] salt,
        int    iterationCount)
    {
        for (int i = 0; i != password.length; i++)
        {
            digest.update((byte)password[i]);
        }
        
        digest.update(salt);

        byte[] digestBytes = digest.digest();
        for (int i = 1; i < iterationCount; i++)
        {
            digest.update(digestBytes);
            digestBytes = digest.digest();
        }

        return digestBytes;
    }
}
