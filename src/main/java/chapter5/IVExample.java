package chapter5;

import java.security.AlgorithmParameters;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.util.ASN1Dump;

/**
 * Example showing IV encoding
 */
public class IVExample
{

    public static void main(String[] args)
        throws Exception
    {
        // set up the parameters object
        AlgorithmParameters	params = AlgorithmParameters.getInstance("AES", "BC");
        IvParameterSpec		ivSpec = new IvParameterSpec(new byte[16]);
        
        params.init(ivSpec);
        
        // look at the ASN.1 encodng.
        ASN1InputStream     aIn = new ASN1InputStream(params.getEncoded("ASN.1"));
        
        System.out.println(ASN1Dump.dumpAsString(aIn.readObject()));
    }
}
