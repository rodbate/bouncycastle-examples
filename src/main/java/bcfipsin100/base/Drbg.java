package bcfipsin100.base;

import java.security.SecureRandom;

import bcfipsin100.util.ExValues;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.util.encoders.Hex;

public class Drbg
{
    public static void setDefaultDrbg()
    {
        EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);

        FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512.fromEntropySource(entSource)
                                        .setSecurityStrength(256)
                                        .setEntropyBitsRequired(256);

        // The SecureRandom built will be used where no SecureRandom is provided and one is needed.
        CryptoServicesRegistrar.setSecureRandom(drgbBldr.build(ExValues.Nonce, false));
    }

    // in this case we're building a DRBG with prediction resistance set to false - this DRBG
    // will only reseed when it needs to.
    public static SecureRandom buildDrbg()
    {
        EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);

        FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512_HMAC.fromEntropySource(entSource)
                                        .setSecurityStrength(256)
                                        .setEntropyBitsRequired(256);

        return drgbBldr.build(ExValues.Nonce, false);
    }

    // in this case we're building a DRBG with prediction resistance set to true - this DRBG
    // will reseed on each invocation.
    public static SecureRandom buildDrbgForKeys()
    {
        EntropySourceProvider entSource = new BasicEntropySourceProvider(new SecureRandom(), true);

        FipsDRBG.Builder drgbBldr = FipsDRBG.SHA512_HMAC.fromEntropySource(entSource)
                                        .setSecurityStrength(256)
                                        .setEntropyBitsRequired(256)
                                        .setPersonalizationString(ExValues.PersonalizationString);

        return drgbBldr.build(ExValues.Nonce, true);
    }

    public static void main(String[] args)
    {
        setDefaultDrbg();

        byte[] data = new byte[32];

        SecureRandom drgb1 = buildDrbg();

        drgb1.nextBytes(data);

        System.out.println("drgb1: " + Hex.toHexString(data));

        drgb1.nextBytes(data);

        System.out.println("drgb1: " + Hex.toHexString(data));

        SecureRandom drgb2 = buildDrbgForKeys();

        drgb2.nextBytes(data);

        System.out.println("drgb2: " + Hex.toHexString(data));

        drgb2.nextBytes(data);

        System.out.println("drgb2: " + Hex.toHexString(data));
    }
}
