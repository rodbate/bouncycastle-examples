package chapter10;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500PrivateCredential;

/**
 * Create the various credentials for an SSL session
 */
public class CreateKeyStores
{
    public static void main(String[] args)
        throws Exception
    {
        X500PrivateCredential    rootCredential = Utils.createRootCredential();
        X500PrivateCredential    interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential    endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
        
        // client credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        
        keyStore.load(null, null);
        
        keyStore.setKeyEntry(Utils.CLIENT_NAME, endCredential.getPrivateKey(), Utils.CLIENT_PASSWORD, 
                new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate() });
        
        keyStore.store(new FileOutputStream(Utils.CLIENT_NAME + ".p12"), Utils.CLIENT_PASSWORD);
        
        // trust store for client
        keyStore = KeyStore.getInstance("JKS");
        
        keyStore.load(null, null);
        
        keyStore.setCertificateEntry(Utils.SERVER_NAME, rootCredential.getCertificate());
        
        keyStore.store(new FileOutputStream(Utils.TRUST_STORE_NAME + ".jks"), Utils.TRUST_STORE_PASSWORD);
        
        // server credentials
        keyStore = KeyStore.getInstance("JKS");
        
        keyStore.load(null, null);
        
        keyStore.setKeyEntry(Utils.SERVER_NAME, rootCredential.getPrivateKey(), Utils.SERVER_PASSWORD,
                new Certificate[] { rootCredential.getCertificate() });
        
        keyStore.store(new FileOutputStream(Utils.SERVER_NAME + ".jks"), Utils.SERVER_PASSWORD);
    }
}
