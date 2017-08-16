package bcfipsin100.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import bcfipsin100.base.EC;
import bcfipsin100.base.Setup;
import bcfipsin100.cert.Cert;
import bcfipsin100.pbeks.KeyStr;

public class HttpsWithClientAuth
{
    private static final String HOST = "localhost";
    private static final int PORT_NO = 9020;

    public static class HttpsAuthClient
        implements Util.BlockingCallable
    {
        private final KeyStore trustStore;
        private final KeyStore clientStore;
        private final char[] clientKeyPass;
        private final CountDownLatch latch;

        public HttpsAuthClient(KeyStore trustStore, KeyStore clientStore, char[] clientKeyPass)
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

            clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), null);

            SSLSocketFactory fact = clientContext.getSocketFactory();

            URL url = new URL("https://"+ HOST + ":" + PORT_NO);
            HttpsURLConnection httpsConnection = (HttpsURLConnection)url.openConnection();

            httpsConnection.setSSLSocketFactory(fact);
            httpsConnection.setHostnameVerifier(new LocalHostVerifier());
            httpsConnection.connect();

            InputStream in = httpsConnection.getInputStream();

            int ch;
            while ((ch = in.read()) >= 0)
            {
                System.out.print((char)ch);
            }

            latch.countDown();

            return null;
        }

        public void await()
            throws InterruptedException
        {
            latch.await();
        }

        private class LocalHostVerifier
            implements HostnameVerifier
        {
            public boolean verify(String hostName, SSLSession session)
            {
                try
                {
                    X500Principal hostID = (X500Principal)session.getPeerPrincipal();

                    return hostName.equals("localhost") && hostID.getName().equals("CN=Issuer CA");
                }
                catch (Exception e)
                {
                    return false;
                }
            }
        }
    }

    public static class HttpsAuthServer
        implements Util.BlockingCallable
    {
        private final KeyStore serverStore;
        private final char[] keyPass;
        private final KeyStore trustStore;
        private final CountDownLatch latch;

        HttpsAuthServer(KeyStore serverStore, char[] keyPass, KeyStore trustStore)
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

            serverContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), null);

            SSLServerSocketFactory fact = serverContext.getServerSocketFactory();
            SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(PORT_NO);

            sSock.setNeedClientAuth(true);

            latch.countDown();

            SSLSocket sslSock = (SSLSocket)sSock.accept();

            readRequest(sslSock.getInputStream());
            sendResponse(sslSock.getOutputStream());

            sslSock.close();

            return null;
        }

        public void await()
            throws InterruptedException
        {
            latch.await();
        }

        private static String readLine(InputStream in)
            throws IOException
        {
            StringBuilder bld = new StringBuilder();

            int ch;
            while ((ch = in.read()) >= 0 && (ch != '\n'))
            {
                if (ch != '\r')
                    bld.append((char)ch);
            }
            return bld.toString();
        }

        private static void readRequest(
            InputStream in)
            throws IOException
        {

            String line = readLine(in);
            while (line.length() != 0)
            {
                System.out.println("Request: " + line);
                line = readLine(in);
            }
        }

        private static void sendResponse(
            OutputStream out)
        {
            PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(out));
            pWrt.print("HTTP/1.1 200 OK\r\n");
            pWrt.print("Content-Type: text/plain\r\n");
            pWrt.print("\r\n");
            pWrt.print("Hello World!\r\n");
            pWrt.flush();
        }
    }

    private static KeyStore rebuildStore(String storeType, char[] storePassword, byte[] encoding)
        throws GeneralSecurityException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance(storeType);

        keyStore.load(new ByteArrayInputStream(encoding), storePassword);

        return keyStore;
    }

    public static void main(String[] args)
        throws Exception
    {
        char[] storePass = "storePassword".toCharArray();
        char[] keyPass = "keyPassword".toCharArray();

        //Setup.installProvider();

        KeyPair caKeyPair = EC.generateKeyPair();

        X509Certificate caCert = Cert.makeV1Certificate(caKeyPair.getPrivate(), caKeyPair.getPublic());

        KeyStore keyStore = rebuildStore("jks", storePass, KeyStr.storePrivateKey(storePass, keyPass, caKeyPair.getPrivate(), new X509Certificate[]{caCert}));

        Util.runClientAndServer(new HttpsAuthServer(keyStore, keyPass, keyStore), new HttpsAuthClient(keyStore, keyStore, keyPass));
    }
}
