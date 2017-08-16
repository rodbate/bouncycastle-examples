package chapter5;

import java.util.Date;

import org.bouncycastle.asn1.*;

/**
 * Implementation of an example ASN.1 structure.
 * <pre>
 * MyStructure ::= SEQUENCE {
 *                   version INTEGER DEFAULT 0,
 *                   created GeneralizedTime,
 *                   baseData OCTET STRING,
 *                   extraData [0] UTF8String OPTIONAL,
 *                   commentData [1] UTF8String OPTIONAL }
 * <pre>
 * 
 */
public class MyStructure implements ASN1Encodable
{
    private DERInteger         version;
    private DERGeneralizedTime created;
    private ASN1OctetString    baseData;
    private DERUTF8String      extraData = null;
    private DERUTF8String      commentData = null;
    
    /**
     * Constructor from an ASN.1 SEQUENCE
     */
    public MyStructure(
        ASN1Sequence    seq)
    {
        int index = 0;
        
        // check for version field
        if (seq.getObjectAt(0) instanceof DERInteger)
        {
            this.version = (DERInteger)seq.getObjectAt(0);
            index++;
        }
        else
        {
            this.version = new DERInteger(0);
        }
        
        this.created = (DERGeneralizedTime)seq.getObjectAt(index++);
        this.baseData = (ASN1OctetString)seq.getObjectAt(index++);
        
        // check for optional fields
        for (int i = index; i != seq.size(); i++)
        {
            ASN1TaggedObject	t = (ASN1TaggedObject)seq.getObjectAt(i);
            
            switch (t.getTagNo())
            {
            case 0:
                extraData = DERUTF8String.getInstance(t, false);
                break;
            case 1:
                commentData = DERUTF8String.getInstance(t, false);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag " + t.getTagNo() + " in constructor");
            }
        }
    }
    
    /**
     * Constructor from corresponding Java objects and primitives.
     */
    public MyStructure(
        int     version,
        Date	created,
        byte[]  baseData,
        String  extraData,
        String  commentData)
    {
        this.version = new DERInteger(version);
        this.created = new DERGeneralizedTime(created);
        this.baseData = new DEROctetString(baseData);
        
        if (extraData != null)
        {
            this.extraData = new DERUTF8String(extraData);
        }
        
        if (commentData != null)
        {
            this.commentData = new DERUTF8String(commentData);
        }
    }
    
    /* 
     * Produce an object suitable for writing to an ASN1/DEROutputStream
     */
    public ASN1Object toASN1Object()
    {
        ASN1EncodableVector	v = new ASN1EncodableVector();
        
        if (version.getValue().intValue() != 0)
        {
            v.add(version);
        }
        
        v.add(created);
        v.add(baseData);
        
        if (extraData != null)
        {
            v.add(new DERTaggedObject(false, 0, extraData));
        }
        
        if (commentData != null)
        {
            v.add(new DERTaggedObject(false, 1, commentData));
        }
        
        return new DERSequence(v);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return null;
    }
}
