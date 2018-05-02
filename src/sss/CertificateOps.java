/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 *
 * @author pr3
 */
public class CertificateOps {

    private X509Certificate createCert(PrivateKey serverPrivateKey, KeyPair clientKeys) throws IOException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());
        String path = Paths.get("").toAbsolutePath().toString();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(path+"\\"+"X509_cert_server.cer");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();

        Date startDate = new Date(System.currentTimeMillis());                // time from which certificate is valid
        Date expiryDate = new Date(System.currentTimeMillis() + 30L * 365L * 24L * 60L * 60L * 1000L);
        SecureRandom rand = new SecureRandom();// time after which certificate is not valid
        BigInteger serialNumber = new BigInteger(8, rand);       // serial number for certificate
        PrivateKey caKey = serverPrivateKey;              // private key of the certifying authority (ca) certificate
        X509Certificate caCert = cert;        // public key certificate of the certifying authority
        // public/private key pair that we are creating certificate for
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(clientKeys.getPublic());
        certGen.setSignatureAlgorithm("SHA256withECDSA");

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure());

        try {
            X509Certificate certClient = certGen.generate(caKey, "BC");
            return certClient;//
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private X509Certificate[] generateCertificateChain(KeyPair clientKeys) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String path = Paths.get("").toAbsolutePath().toString();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(path+"\\"+"X509_cert_server.cer");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();

            FileInputStream is = new FileInputStream(path+"\\"+"keystore.jks");

            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(is, "password".toCharArray());
            is.close();
            String alias = "alias";

            Key key = keystore.getKey(alias, "password".toCharArray());
            if (key instanceof PrivateKey) {
                PrivateKey serverPrivateKey = (PrivateKey) key;
                X509Certificate clientCert = createCert(serverPrivateKey, clientKeys);
                X509Certificate[] certChain = {cert, createCert(serverPrivateKey, clientKeys)};
                return certChain;
            }

        } catch (CertificateEncodingException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
