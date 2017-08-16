package bcfipsin100.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class ExValues
{
    public static final long THIRTY_DAYS = 1000L * 60 * 60 * 24 * 30;

    public static final SecretKey SampleAesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");

    public static final SecretKey SampleTripleDesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617"), "TripleDES");

    public static final SecretKey SampleHMacKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f10111213"), "HmacSHA512");

    public static final byte[] SampleInput = Strings.toByteArray("Hello World!");

    public static final byte[] SampleTwoBlockInput = Strings.toByteArray("Some cipher modes require more than one block");

    public static final byte[] Nonce = Strings.toByteArray("number only used once");

    public static final byte[] PersonalizationString = Strings.toByteArray("a constant personal marker");

    public static final byte[] Initiator = Strings.toByteArray("Initiator");

    public static final byte[] Recipient = Strings.toByteArray("Recipient");

    public static final byte[] UKM = Strings.toByteArray("User keying material");
}
