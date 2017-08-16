package chapter10;

/**
 * Chapter 10 Utils
 */
public class Utils extends chapter9.Utils
{
    /**
     * Host name for our examples to use.
     */
    static final String HOST = "localhost";
    
    /**
     * Port number for our examples to use.
     */
    static final int PORT_NO = 9020;

    /**
     * Names and passwords for the key store entries we need.
     */
    public static final String SERVER_NAME = "server";
    public static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();

    public static final String CLIENT_NAME = "client";
    public static final char[] CLIENT_PASSWORD = "clientPassword".toCharArray();

    public static final String TRUST_STORE_NAME = "trustStore";
    public static final char[] TRUST_STORE_PASSWORD = "trustPassword".toCharArray();
}
