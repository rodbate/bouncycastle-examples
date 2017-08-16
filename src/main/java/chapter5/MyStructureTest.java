package chapter5;

import java.util.Date;

import chapter4.Utils;

/**
 * Test for MyStructure
 */
public class MyStructureTest
{
    public static void main(String[] args)
        throws Exception
    {
        byte[] baseData = new byte[5];
        Date   created = new Date(0); // 1/1/1970
        
        /*MyStructure	structure = new MyStructure(0, created, baseData, null, null);
        
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        
        structure = new MyStructure(0, created, baseData, "hello", null);
        
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        
        structure = new MyStructure(0, created, baseData, null, "world");
        
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        
        structure = new MyStructure(0, created, baseData, "hello", "world");
        
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        
        structure = new MyStructure(1, created, baseData, null, null);
        
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }*/
    }
}
