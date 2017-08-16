package chapter10;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.Principal;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Basic SSL Server with optional client authentication.
 */
public class HTTPSServerExample
    extends SSLServerWithClientAuthIdExample
{
    /**
     * Read a HTTP request
     */
    private static void readRequest(
        InputStream in) 
        throws IOException
    {
        System.out.print("Request: ");
        int ch = 0;
        int lastCh = 0;
        while ((ch = in.read()) >= 0 && (ch != '\n' && lastCh != '\n'))
        {
            System.out.print((char)ch);
            if (ch != '\r')
                lastCh = ch;
        }
        
        System.out.println();
    }
    
    /**
     * Send a response
     */
    private static void sendResponse(
        OutputStream out)
    {
        PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(out));
        pWrt.print("HTTP/1.1 200 OK\r\n");
        pWrt.print("Content-Type: text/html\r\n");
        pWrt.print("\r\n");
        pWrt.print("<html>\r\n");
        pWrt.print("<body>\r\n");
        pWrt.print("Hello World!\r\n");
        pWrt.print("</body>\r\n");
        pWrt.print("</html>\r\n");
        pWrt.flush();
    }
    
    public static void main(
        String[] args)
        throws Exception
    {
		SSLContext             sslContext = createSSLContext();
        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Utils.PORT_NO);
    
        // client authenticate where possible
        sSock.setWantClientAuth(true);
        
        for (;;) 
        {
            SSLSocket sslSock = (SSLSocket)sSock.accept();
            
            try
            {
                sslSock.startHandshake();
            }
            catch (IOException e)
            {
                continue;
            }
            
            readRequest(sslSock.getInputStream());
            
            SSLSession session = sslSock.getSession();
            
            try
            {
                Principal clientID = session.getPeerPrincipal();

                System.out.println("client identified as: " + clientID);
            }
            catch (SSLPeerUnverifiedException e)
            {
                System.out.println("client not authenticated");
            }
            
            sendResponse(sslSock.getOutputStream());
            
            sslSock.close();
        }
    }
}