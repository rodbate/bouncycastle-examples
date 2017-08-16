package chapter9;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;

/**
 * a simple example that creates and processes an compressed mail message.
 */
public class CompressedMailExample
{
    public static void main(
        String args[])
        throws Exception
    {
        // create the message we want compressed
        MimeBodyPart    dataPart = new MimeBodyPart();

        dataPart.setText("Hello world!");
        
        // set up the generator
        SMIMECompressedGenerator  gen = new SMIMECompressedGenerator();

        // generate the compressed message
        /*MimeBodyPart comPart = gen.generate(dataPart, SMIMECompressedGenerator.ZLIB);

        // create the mail message
        MimeMessage mail = Utils.createMimeMessage("example compressed message", comPart.getContent(), comPart.getContentType());

        // create the enveloped object from the mail message
        SMIMECompressed  compressed = new SMIMECompressed(mail);

        // uncompression step
        MimeBodyPart     recoveredPart = SMIMEUtil.toMimeBodyPart(compressed.getContent());

        // content display step
        System.out.print("Content: ");
        System.out.println(recoveredPart.getContent());*/
    }
}