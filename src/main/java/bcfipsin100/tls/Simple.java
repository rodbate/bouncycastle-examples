package bcfipsin100.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import bcfipsin100.pbeks.KeyStr;

public class Simple
{
    private static final String HOST = "localhost";
    private static final int PORT_NO = 9020;

    public static class SimpleClient
        implements Util.BlockingCallable
    {
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        public SimpleClient(KeyStore trustStore)
        {
            this.trustStore = trustStore;
            this.latch = new CountDownLatch(1);
        }

        public Object call()
            throws Exception
        {
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");

            trustMgrFact.init(trustStore);

            SSLContext clientContext = SSLContext.getInstance("TLS");

            clientContext.init(null, trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BCFIPS"));

            SSLSocketFactory fact = clientContext.getSocketFactory();
            SSLSocket cSock = (SSLSocket)fact.createSocket(HOST, PORT_NO);

            Util.doClientProtocol(cSock, "Hello");

            latch.countDown();

            return null;
        }

        public void await()
            throws InterruptedException
        {
            latch.await();
        }
    }

    public static class SimpleServer
        implements Util.BlockingCallable
    {
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final CountDownLatch latch;

        SimpleServer(KeyStore serverStore, char[] keyPass)
        {
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.latch = new CountDownLatch(1);
        }

        public Object call()
            throws Exception
        {
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");

            keyMgrFact.init(serverStore, keyPass);

            SSLContext serverContext = SSLContext.getInstance("TLS");

            serverContext.init(keyMgrFact.getKeyManagers(), null, SecureRandom.getInstance("DEFAULT", "BCFIPS"));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);

            latch.countDown();

            SSLSocket sslSock = (SSLSocket)sSock.accept();

            Util.doServerProtocol(sslSock, "World");

            return null;
        }

        public void await()
            throws InterruptedException
        {
            latch.await();
        }
    }

    private static KeyStore rebuildStore(String storeType, char[] storePassword, byte[] encoding)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance(storeType, "BCFIPS");

        keyStore.load(new ByteArrayInputStream(encoding), storePassword);

        return keyStore;
    }

    public static void main(String[] args)
        throws Exception
    {
        char[] storePass = "storePassword".toCharArray();
        char[] keyPass = "keyPassword".toCharArray();

        Setup.installProvider();

        KeyPair caKeyPair = EC.generateKeyPair();

        X509Certificate caCert = Cert.makeV1Certificate(caKeyPair.getPrivate(), caKeyPair.getPublic());

        KeyStore keyStore = rebuildStore("BCFKS", storePass, KeyStr.storePrivateKey(storePass, keyPass, caKeyPair.getPrivate(), new X509Certificate[]{caCert}));

        Util.runClientAndServer(new SimpleServer(keyStore, keyPass), new SimpleClient(keyStore));
    }
}
