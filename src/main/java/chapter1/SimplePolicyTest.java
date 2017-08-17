package chapter1;

import chapter2.*;
import chapter2.Utils;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Test to make sure the unrestricted policy files are installed.
 */
public class SimplePolicyTest
{
    public static void main(
        String[] args)
    throws Exception
    {
        byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x09, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

        System.out.println("Plain input : " + Utils.toHex(data) + "  bytes : " + data.length);
        // create a 64 bit secret key from raw bytes

        SecretKey key64 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07 }, "Blowfish");

        // create a cipher and attempt to encrypt the data block with our key

        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");

        c.init(Cipher.ENCRYPT_MODE, key64);
        byte[] bytes64 = c.doFinal(data);
        System.out.println("64 Cipher : " + chapter2.Utils.toHex(bytes64) + "  bytes : " + bytes64.length);

        // create a 192 bit secret key from raw bytes

        SecretKey key192 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17 }, "Blowfish");

        // now try encrypting with the larger key

        c.init(Cipher.ENCRYPT_MODE, key192);
        byte[] bytes192 = c.doFinal(data);
        System.out.println("192 Cipher : " + chapter2.Utils.toHex(bytes192) + "  bytes : " + bytes192.length);


        //decryption 64
        c.init(Cipher.DECRYPT_MODE, key64);
        byte[] plain64 = c.doFinal(bytes64);
        System.out.println("64 Plain : " + chapter2.Utils.toHex(plain64) + "  bytes : " + plain64.length);

        //decryption 192
        c.init(Cipher.DECRYPT_MODE, key192);
        byte[] plain192 = c.doFinal(bytes192);
        System.out.println("192 Plain : " + chapter2.Utils.toHex(plain192) + "  bytes : " + plain192.length);

        //decryption 192 -- 2
        c.init(Cipher.DECRYPT_MODE, key192);
        byte[] plain192_2 = new byte[c.getOutputSize(bytes192.length)];
        int pLen = c.update(bytes192, 0, bytes192.length, plain192_2, 0);
        pLen += c.doFinal(plain192_2, pLen);
        System.out.println("192 Plain 2 : " + chapter2.Utils.toHex(plain192_2) + "  bytes : " + pLen);

        //decryption 192 -- 3
        c.init(Cipher.DECRYPT_MODE, key192);
        byte[] plain192_3 = new byte[c.getOutputSize(bytes192.length)];
        int pLen3 = c.doFinal(bytes192, 0, bytes192.length, plain192_3, 0);
        System.out.println("192 Plain 3 : " + chapter2.Utils.toHex(plain192_3) + "  bytes : " + pLen3);
    }
}

