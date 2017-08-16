package chapter10;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Basic SSL Client - using the '!' protocol.
 */
public class SSLClientExample
{
    /**
     * Carry out the '!' protocol - client side.
     */
    static void doProtocol(
        Socket cSock)
        throws IOException
    {
        OutputStream     out = cSock.getOutputStream();
        InputStream      in = cSock.getInputStream();
        
        out.write(Utils.toByteArray("World"));
        out.write('!');
        
        int ch = 0;
        while ((ch = in.read()) != '!')
        {
            System.out.print((char)ch);
        }
        
        System.out.println((char)ch);
    }
    
    public static void main(
        String[] args)
        throws Exception
    {
        SSLSocketFactory fact = (SSLSocketFactory)SSLSocketFactory.getDefault();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Utils.HOST, Utils.PORT_NO);
        
        doProtocol(cSock);
    }
}
