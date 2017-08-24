package chapter10;

import rb.BaseClass;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;

import javax.net.ssl.*;

/**
 * Basic SSL Server - using the '!' protocol.
 */
public class SSLServerExample extends BaseClass
{
    /**
     * Carry out the '!' protocol - server side.
     */
    static void doProtocol(
        Socket sSock)
        throws IOException
    {
        System.out.println("session started.");
        
        InputStream in = sSock.getInputStream();
        OutputStream out = sSock.getOutputStream();

        out.write(Utils.toByteArray("Hello "));
        
        int ch = 0;
        while ((ch = in.read()) != '!')
        {
            out.write(ch);
        }
        
        out.write('!');

        sSock.close();
        
        System.out.println("session closed.");
    }

    private static SSLContext createSslContext() throws Exception {
        KeyManagerFactory kmfc = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("server.jks"), Utils.SERVER_PASSWORD);
        kmfc.init(keyStore, Utils.SERVER_PASSWORD);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmfc.getKeyManagers(), null, null);
        return sslContext;
    }
    
    public static void main(
        String[] args)
        throws Exception
    {

        //-Djavax.net.ssl.keyStore=server.jks -Djavax.net.ssl.keyStorePassword=serverPassword
        //SSLServerSocketFactory fact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        SSLContext sslContext = createSslContext();
        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        System.out.println("default cipher suites : " + Arrays.toString(fact.getDefaultCipherSuites()));
        System.out.println("supported cipher suites : " + Arrays.toString(fact.getSupportedCipherSuites()));
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Utils.PORT_NO);
        SSLSocket sslSock = (SSLSocket)sSock.accept();
        sslSock.addHandshakeCompletedListener(event -> {
            System.out.println("current cipher suite : " + event.getCipherSuite());
            System.out.println("session protocol : " + event.getSession().getProtocol());
        });
        doProtocol(sslSock);


    }
}
