package chapter1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.*;

/**
 * List the available capabilities for ciphers, key agreement, macs, message
 * digests, signatures and other objects in the BC provider.
 */
public class ListBCCapabilities
{
    public static void main(
        String[]    args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Provider	provider = Security.getProvider("BC");
        if (provider == null) {
            System.out.println("provider BC does not exist");
            System.exit(-1);
        }

        Map<String, Set<String>> map = new HashMap<>();

        for (Object o : provider.keySet()) {
            String entry = (String) o;

            // this indicates the entry refers to another entry

            if (entry.startsWith("Alg.Alias.")) {
                entry = entry.substring("Alg.Alias.".length());
            }

            String factoryClass = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(factoryClass.length() + 1);

            Set<String> set = map.computeIfAbsent(factoryClass, k -> new HashSet<>());
            set.add(name);
        }

        //FileOutputStream fos = new FileOutputStream("");

        FileWriter writer = new FileWriter("C:\\Users\\Administrator\\Desktop\\bc.txt");
        for (Map.Entry<String, Set<String>> entry : map.entrySet()) {
            //System.out.println(String.format("------------------- [%s] ----------------\n", entry.getKey()));
            writer.write(String.format("------------------- [%s] ----------------\n", entry.getKey()));
            for (String en : entry.getValue()) {
                //System.out.println(en);
                writer.write(en + "\n");
            }
            writer.write("\n");
            System.out.println();
            System.out.println();
        }

        writer.close();
    }
}
