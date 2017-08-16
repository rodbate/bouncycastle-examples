package chapter3;

import java.security.MessageDigest;

/**
 * mask generator function, as described in PKCS1v2.
 */
public class MGF1
{
    private MessageDigest digest;
    
    /**
     * Create a version of MGF1 for the given digest.
     * 
     * @param digest digest to use as the basis of the function.
     */
    public MGF1(
        MessageDigest digest)
    {
        this.digest = digest;
    }
    
    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }
    
    /**
     * Generate the mask.
     * 
     * @param seed source of input bytes for initial digest state
     * @param length length of mask to generate
     * 
     * @return a byte array containing a MGF1 generated mask
     */
    public byte[] generateMask(
        byte[]  seed,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  C = new byte[4];
        int     counter = 0;
        int     hLen = digest.getDigestLength();

        digest.reset();

        while (counter < (length / hLen))
        {
            ItoOSP(counter, C);

            digest.update(seed);
            digest.update(C);

            System.arraycopy(digest.digest(), 0, mask, counter * hLen, hLen);
            
            counter++;
        }

        if ((counter * hLen) < length)
        {
            ItoOSP(counter, C);

            digest.update(seed);
            digest.update(C);

            System.arraycopy(digest.digest(), 0, mask, counter * hLen, mask.length - (counter * hLen));
        }

        return mask;
    }
    
    public static void main(
       String[] args)
       throws Exception
    {
        MGF1	mgf1 = new MGF1(MessageDigest.getInstance("SHA-1", "BC"));
        byte[]  source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        
       System.out.println(Utils.toHex(mgf1.generateMask(source, 20)));
    }
}
