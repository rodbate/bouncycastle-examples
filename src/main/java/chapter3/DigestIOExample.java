package chapter3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

/**
 * Basic IO example using SHA1
 */
public class DigestIOExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]          input = new byte[] { 
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };;
        
        MessageDigest   hash = MessageDigest.getInstance("SHA1");
        
        System.out.println("input     : " + Utils.toHex(input));
        
        // input pass
        
        ByteArrayInputStream	bIn = new ByteArrayInputStream(input);
        DigestInputStream		dIn = new DigestInputStream(bIn, hash);
        ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
        
        int	ch;
        while ((ch = dIn.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        byte[] newInput = bOut.toByteArray();
        
        System.out.println("in digest : " + Utils.toHex(dIn.getMessageDigest().digest()));
        
        // output pass
        
        bOut = new ByteArrayOutputStream();
        
        DigestOutputStream      dOut = new DigestOutputStream(bOut, hash);

        dOut.write(newInput);
        
        dOut.close();
        
        System.out.println("out digest: " + Utils.toHex(dOut.getMessageDigest().digest()));
    }
}
