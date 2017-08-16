package chapter5;

import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.util.ASN1Dump;


/**
 * Example for ASN1Dump using MyStructure.
 */
public class ASN1DumpExample
{
    public static void main(String[] args)
        throws Exception
    {
        /*byte[] baseData = new byte[5];
        Date   created = new Date(0); // 1/1/1970
        
        MyStructure	structure = new MyStructure(0, created, baseData, "hello", "world");
        
        System.out.println(ASN1Dump.dumpAsString(structure));
        
        structure = new MyStructure(1, created, baseData, "hello", "world");
        
        System.out.println(ASN1Dump.dumpAsString(structure));
        
        ASN1InputStream	aIn = new ASN1InputStream(structure.getEncoded());
        
        System.out.println(ASN1Dump.dumpAsString(aIn.readObject()));*/
    }
}
