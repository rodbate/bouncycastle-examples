package chapter10;

import java.io.InputStream;
import java.net.URL;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

/**
 * SSL Client with client side authentication.
 */
public class HTTPSClientExample
    extends SSLClientWithClientAuthTrustExample
{
    /**
     * Verifier to check host has identified itself using "Test CA Certificate".
     */
    private static class Validator
        implements HostnameVerifier
    {
        public boolean verify(String hostName, SSLSession session)
        {
            try
            {
                X500Principal hostID = (X500Principal)session.getPeerPrincipal();
                
                return hostID.getName().equals("CN=Test CA Certificate");
            }
            catch (Exception e)
            {
                return false;
            }
        }
    }
    
    public static void main(
        String[] args)
        throws Exception
    {
		SSLContext       sslContext = createSSLContext();
		SSLSocketFactory fact = sslContext.getSocketFactory();
		
		// specify the URL and connection attributes
		URL url = new URL("https://"+ Utils.HOST + ":" + Utils.PORT_NO);
		
		HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
		
		connection.setSSLSocketFactory(fact);
		connection.setHostnameVerifier(new Validator());
		
		connection.connect();
		
		// read the response
		InputStream  in = connection.getInputStream();
        
        int ch;
        while ((ch = in.read()) >= 0)
        {
            System.out.print((char)ch);
        }
    }
}