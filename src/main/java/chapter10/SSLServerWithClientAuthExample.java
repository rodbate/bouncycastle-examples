package chapter10;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Basic SSL Server with client authentication.
 */
public class SSLServerWithClientAuthExample
    extends SSLServerExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        SSLServerSocketFactory fact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Utils.PORT_NO);
    
        sSock.setNeedClientAuth(true);
        
        SSLSocket sslSock = (SSLSocket)sSock.accept();
        
        doProtocol(sslSock);
    }
}