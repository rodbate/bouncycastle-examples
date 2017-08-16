package bcfipsin100.base;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import bcfipsin100.util.ExValues;
import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsXOFOperatorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class Shs
{
    public static byte[] calculateDigest(byte[] data)
        throws GeneralSecurityException
    {
        MessageDigest hash = MessageDigest.getInstance("SHA512", "BCFIPS");

        return hash.digest(data);
    }

    public static byte[] calculateSha3Digest(byte[] data)
        throws GeneralSecurityException
    {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");

        return hash.digest(data);
    }

    public static SecretKey generateKey()
        throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512", "BCFIPS");

        keyGenerator.init(256);

        return keyGenerator.generateKey();
    }

    public static byte[] calculateHmac(SecretKey key, byte[] data)
        throws GeneralSecurityException
    {
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");

        hmac.init(key);

        return hmac.doFinal(data);
    }

    public static byte[] calculateShakeOutput(byte[] data)
        throws IOException
    {
        FipsXOFOperatorFactory<FipsSHS.Parameters> factory = new FipsSHS.XOFOperatorFactory<>();

        OutputXOFCalculator<FipsSHS.Parameters> calculator = factory.createOutputXOFCalculator(FipsSHS.SHAKE256);

        OutputStream digestStream = calculator.getFunctionStream();

        digestStream.write(data);

        digestStream.close();

        return calculator.getFunctionOutput(32);
    }

    public static byte[] calculateShakeOutputContinuous(byte[] data)
        throws IOException
    {
        FipsXOFOperatorFactory<FipsSHS.Parameters> factory = new FipsSHS.XOFOperatorFactory<FipsSHS.Parameters>();

        OutputXOFCalculator<FipsSHS.Parameters> calculator = factory.createOutputXOFCalculator(FipsSHS.SHAKE256);

        OutputStream digestStream = calculator.getFunctionStream();

        digestStream.write(data);

        digestStream.close();

        return Arrays.concatenate(calculator.getFunctionOutput(16), calculator.getFunctionOutput(16));
    }

    public static void main(String[] args)
        throws GeneralSecurityException, IOException
    {
        Setup.installProvider();

        System.err.println("Digest       : " + Hex.toHexString(calculateDigest(ExValues.SampleInput)));

        System.err.println("Digest (SHA3): " + Hex.toHexString(calculateSha3Digest(ExValues.SampleInput)));

        SecretKey hmacKey = generateKey();

        System.err.println("HMAC: " + Hex.toHexString(calculateHmac(hmacKey, ExValues.SampleInput)));

        System.err.println("SHAKE:              " + Hex.toHexString(calculateShakeOutput(ExValues.SampleInput)));

        System.err.println("SHAKE (continuous): " + Hex.toHexString(calculateShakeOutputContinuous(ExValues.SampleInput)));
    }
}
