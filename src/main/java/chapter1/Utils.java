package chapter1;

/**
 * Static utility methods.
 */
public class Utils
{
    /**
     * Return a string of length len made up of blanks.
     * 
     * @param len the length of the output String.
     * @return the string of blanks.
     */
    public static String makeBlankString(
        int	len)
    {
        char[]   buf = new char[len];
        
        for (int i = 0; i != buf.length; i++)
        {
            buf[i] = ' ';
        }
        
        return new String(buf);
    }
}
