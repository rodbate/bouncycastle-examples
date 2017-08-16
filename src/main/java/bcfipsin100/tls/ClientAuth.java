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

public class ClientAuth
{
    private static final String HOST = "localhost";
    private static final int PORT_NO = 9020;

    public static class ClientAuthClient
        implements Util.BlockingCallable
    {
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        public ClientAuthClient(KeyStore trustStore, KeyStore clientStore, char[] clientKeyPass)
        {
            this.trustStore = trustStore;
            this.clientStore = clientStore;
            this.clientKeyPass = clientKeyPass;
            this.latch = new CountDownLatch(1);
        }

        public Object call()
            throws Exception
        {
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");

            trustMgrFact.init(trustStore);

            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");

            keyMgrFact.init(clientStore, clientKeyPass);

            SSLContext clientContext = SSLContext.getInstance("TLS");

            clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BCFIPS"));

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

    public static class ClientAuthServer
        implements Util.BlockingCallable
    {
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        ClientAuthServer(KeyStore serverStore, char[] keyPass, KeyStore trustStore)
        {
            this.serverStore = serverStore;
            this.keyPass = keyPass;
            this.trustStore = trustStore;
            this.latch = new CountDownLatch(1);
        }

        public Object call()
            throws Exception
        {
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");

            keyMgrFact.init(serverStore, keyPass);

            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");

            trustMgrFact.init(trustStore);

            SSLContext serverContext = SSLContext.getInstance("TLS");

            serverContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BCFIPS"));

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);

            sSock.setNeedClientAuth(true);

            latch.countDown();

            SSLSocket sslSock = (SSLSocket)sSock.accept();

            Util.doServerProtocol(sslSock, "World");

            sslSock.close();

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

        Util.runClientAndServer(new ClientAuthServer(keyStore, keyPass, keyStore), new ClientAuthClient(keyStore, keyStore, keyPass));
    }
}
