package rb;

import chapter2.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 *
 * Created by rodbate on 2017/8/17.
 */
public class TTSS1 extends BaseClass {


    public static void main(String[] args) throws Exception {

        byte[] key = {0x00, 0x01, 0x22, 0x11, 0x33, 0x44, 0x55, 0x66,
                        0x02, 0x13, 0x23, 0x12, 0x18, 0x1f, 0x1e, 0x0a};

        byte[] data = "T S M D !!!".getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES", "BC");

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] cipherText = cipher.doFinal(data);
        System.out.println("cipher : " + Utils.toHex(cipherText));

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + new String(plainText, "utf-8"));
    }
}
