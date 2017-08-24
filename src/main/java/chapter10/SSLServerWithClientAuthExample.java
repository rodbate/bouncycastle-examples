package chapter10;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

/**
 * Basic SSL Server with client authentication.
 */
public class SSLServerWithClientAuthExample
    extends SSLServerExample
{


    private static SSLContext createSslContext() throws Exception {

        KeyManagerFactory kmfc = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("server.jks"), Utils.SERVER_PASSWORD);
        kmfc.init(keyStore, Utils.SERVER_PASSWORD);

        TrustManagerFactory tmfc = TrustManagerFactory.getInstance("SunX509");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("trustStore.jks"), Utils.TRUST_STORE_PASSWORD);
        tmfc.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmfc.getKeyManagers(), tmfc.getTrustManagers(), null);
        return sslContext;
    }


    public static void main(
        String[] args)
        throws Exception
    {
        //-Djavax.net.ssl.keyStore=server.jks
        //-Djavax.net.ssl.keyStorePassword=serverPassword
        //-Djavax.net.ssl.trustStore=trustStore.jks
        //or manual to create ssl context
        //SSLServerSocketFactory fact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        //SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Utils.PORT_NO);

        SSLContext sslContext = createSslContext();
        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Utils.PORT_NO);

        sSock.setNeedClientAuth(true);

        SSLSocket sslSock = (SSLSocket)sSock.accept();
        InetSocketAddress addr = (InetSocketAddress) sslSock.getRemoteSocketAddress();
        System.out.println("Accept request : " + addr.getHostName() + ":" + addr.getPort());
        sslSock.addHandshakeCompletedListener(event -> {
            System.out.println("protocol : " + event.getSession().getProtocol());
        });
        
        doProtocol(sslSock);
    }
}