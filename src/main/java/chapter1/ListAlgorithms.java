package chapter1;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class ListAlgorithms
{
    /**
     * Print out the set entries, indented, one per line, with the name of the set
     * unindented appearing on the first line.
     * 
     * @param setName the name of the set being printed
     * @param algorithms the set of algorithms associated with the given name
     */
    public static void printSet(
        String setName,
        Set<String>	   algorithms)
    {
        System.out.println(setName + ":");
        
        if (algorithms.isEmpty())
        {
            System.out.println("            None available.");
        }
        else
        {
            for (String name : algorithms) {
                System.out.println("            " + name);
            }
        }
    }
    
    /**
     * List the available algorithm names for ciphers, key agreement, macs,
     * message digests and signatures.
     */
    public static void main(String[]    args) {
        Provider[]	providers = Security.getProviders();
        Set<String>			ciphers = new HashSet<>();
        Set<String>			keyAgreements = new HashSet<>();
        Set<String>			macs = new HashSet<>();
        Set<String>			messageDigests = new HashSet<>();
        Set<String>			signatures = new HashSet<>();
        
        for (int i = 0; i != providers.length; i++)
        {

            for (Object o : providers[i].keySet()) {
                String entry = (String) o;

                if (entry.startsWith("Alg.Alias.")) {
                    entry = entry.substring("Alg.Alias.".length());
                }

                if (entry.startsWith("Cipher.")) {
                    ciphers.add(entry.substring("Cipher.".length()));
                } else if (entry.startsWith("KeyAgreement.")) {
                    keyAgreements.add(entry.substring("KeyAgreement.".length()));
                } else if (entry.startsWith("Mac.")) {
                    macs.add(entry.substring("Mac.".length()));
                } else if (entry.startsWith("MessageDigest.")) {
                    messageDigests.add(entry.substring("MessageDigest.".length()));
                } else if (entry.startsWith("Signature.")) {
                    signatures.add(entry.substring("Signature.".length()));
                }
            }
        }
        
        printSet("Ciphers", ciphers);
        printSet("KeyAgreeents", keyAgreements);
        printSet("Macs", macs);
        printSet("MessageDigests", messageDigests);
        printSet("Signatures", signatures);
    }
}
