package chapter9;

import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.security.auth.x500.X500PrivateCredential;


/**
 * Chapter 9 Utils
 */
public class Utils extends chapter8.Utils
{
    public static char[] KEY_PASSWD = "keyPassword".toCharArray();
    
    /**
     * Create a KeyStore containing the a private credential with
     * certificate chain and a trust anchor.
     */
    public static KeyStore createCredentials()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);
        
        X500PrivateCredential    rootCredential = Utils.createRootCredential();
        X500PrivateCredential    interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential    endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
        
        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), KEY_PASSWD, 
                new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate() });

        return store;
    }
    
    /**
     * Build a path using the given root as the trust anchor, and the passed
     * in end constraints and certificate store.
     * <p>
     * Note: the path is built with revocation checking turned off.
     */
    public static PKIXCertPathBuilderResult buildPath(
        X509Certificate  rootCert,
        X509CertSelector endConstraints,
        CertStore        certsAndCRLs)
        throws Exception
    {
        CertPathBuilder       builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);
        
        buildParams.addCertStore(certsAndCRLs);
        buildParams.setRevocationEnabled(false);
        
        return (PKIXCertPathBuilderResult)builder.build(buildParams);
    }
    
    /**
     * Create a MIME message from using the passed in content.
     */
    public static MimeMessage createMimeMessage(
        String subject, 
        Object content, 
        String contentType) 
        throws MessagingException
    {
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
        Address toUser = new InternetAddress("example@bouncycastle.org");

        MimeMessage message = new MimeMessage(session);
        
        message.setFrom(fromUser);
        message.setRecipient(Message.RecipientType.TO, toUser);
        message.setSubject(subject);
        message.setContent(content, contentType);
        message.saveChanges();
        
        return message;
    }
}
