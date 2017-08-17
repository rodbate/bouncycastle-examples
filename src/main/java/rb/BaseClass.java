package rb;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 *
 * Created by rodbate on 2017/8/17.
 */
public abstract class BaseClass {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

}
