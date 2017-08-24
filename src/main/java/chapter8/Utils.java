package chapter8;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500PrivateCredential;

/**
 * Chapter 8 Utils
 */
public class Utils extends chapter7.Utils
{
    public static String ROOT_ALIAS = "root";
    public static String INTERMEDIATE_ALIAS = "intermediate";
    public static String END_ENTITY_ALIAS = "end";
    
    /**
     * Generate a X500PrivateCredential for the root entity.
     */
    public static X500PrivateCredential createRootCredential()
        throws Exception
    {
        KeyPair         rootPair = generateRSAKeyPair();
        X509Certificate rootCert = generateRootCert(rootPair);
        
        return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair         rootPair = generateRSAKeyPair();
        X509Certificate root = generateRootCert(rootPair);

        X500PrivateCredential intermediateCredential = createIntermediateCredential(rootPair.getPrivate(), root);

        X500PrivateCredential endEntityCredential = createEndEntityCredential(intermediateCredential.getPrivateKey(), intermediateCredential.getCertificate());

        System.out.println("ROOT ---------------------  ");
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(System.out));
        writer.writeObject(root);
        writer.flush();
        writer.write("Intermediate ---------------- \n");
        writer.writeObject(intermediateCredential.getCertificate());
        writer.flush();
        writer.write("\n");
        writer.flush();
        writer.writeObject(endEntityCredential.getCertificate());
        writer.close();
    }
    
    /**
     * Generate a X500PrivateCredential for the intermediate entity.
     */
    public static X500PrivateCredential createIntermediateCredential(
        PrivateKey      caKey,
        X509Certificate caCert)
        throws Exception
    {
        KeyPair         interPair = generateRSAKeyPair();
        X509Certificate interCert = generateIntermediateCert(interPair.getPublic(), caKey, caCert);
        
        return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
    }
    
    /**
     * Generate a X500PrivateCredential for the end entity.
     */
    public static X500PrivateCredential createEndEntityCredential(
        PrivateKey      caKey,
        X509Certificate caCert)
        throws Exception
    {
        KeyPair         endPair = generateRSAKeyPair();
        X509Certificate endCert = generateEndEntityCert(endPair.getPublic(), caKey, caCert);
        
        return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
    }
}