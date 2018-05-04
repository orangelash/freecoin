/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 *
 * @author pr3
 */
public class CertificateOps {    
    
   public void generateCertificateSelfSigned(KeyPair kp){  
       //cria um certificado server-server
       try {
           Security.addProvider(new BouncyCastleProvider());
           
           String path = Paths.get("").toAbsolutePath().toString();
           
           Date startDate = new Date(System.currentTimeMillis());                // time from which certificate is valid
           Date expiryDate = new Date(System.currentTimeMillis() + 30L * 365L * 24L * 60L * 60L * 1000L);
           SecureRandom rand = new SecureRandom();// time after which certificate is not valid
           BigInteger serialNumber = new BigInteger(8, rand);       // serial number for certificate
                        // private key of the certifying authority (ca) certificate
           // public key certificate of the certifying authority
           // public/private key pair that we are creating certificate for
           X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
           X500Principal subjectName = new X500Principal("CN=SERVER");
           X500Principal issuerName = new X500Principal("CN=SERVER");
           
           certGen.setSerialNumber(serialNumber);
           certGen.setIssuerDN(issuerName);
           certGen.setNotBefore(startDate);
           certGen.setNotAfter(expiryDate);
           certGen.setSubjectDN(subjectName);
           certGen.setPublicKey(kp.getPublic());
           certGen.setSignatureAlgorithm("SHA256withECDSA");
           
           
           
           
           X509Certificate certServer = certGen.generate(kp.getPrivate(), "BC");
           
           FileOutputStream fout = new FileOutputStream(path + "/" + "server_cert_root.cer");
           ObjectOutput s = new ObjectOutputStream(fout);
           s.writeObject(certServer);
           fout.close();
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
       } catch (FileNotFoundException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (IOException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       }
}

    private X509Certificate createCert(PrivateKey serverPrivateKey, PublicKey clientKeys) throws IOException, CertificateException {
        //Cria um certificado server-client
        Security.addProvider(new BouncyCastleProvider());
        String path = Paths.get("").toAbsolutePath().toString();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(path + "/" +"server_cert_root.cer");
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
        X500Principal subjectName = new X500Principal("CN=CLIENT Nº "+ StringUtil.getHexString(clientKeys.getEncoded()));

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(clientKeys);
        certGen.setSignatureAlgorithm("SHA256withECDSA");

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caCert));

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

    private X509Certificate[] generateCertificateChain(PublicKey clientKeys) {
        //FUNÇÃO PRINCIPAL -> abre o certificado server-server, cria um novo certificado, cria uma certificate chain, guarda usando a publicKey do client 
        
        Security.addProvider(new BouncyCastleProvider());
            String path = Paths.get("").toAbsolutePath().toString();
        
        try{
            System.out.println("enter gener");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(path + "/" + "server_cert_root.cer");
            System.out.println("read server cert");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();

            keyUtils ku = new keyUtils();
            KeyPair kp = ku.LoadKeyPairServer(path, "ECDSA");
            X509Certificate[] certChain = {cert, createCert(kp.getPrivate(), clientKeys)};
            System.out.println("cert chain created");

            FileOutputStream fout = new FileOutputStream(path + "/" + StringUtil.getHexString(clientKeys.getEncoded()) + ".cer");
            ObjectOutput s = new ObjectOutputStream(fout);
            s.writeObject(certChain);
            fout.close();

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
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
    
    
    private void verifyPresentCertificate(PublicKey clientKeys) throws FileNotFoundException, IOException, CertificateException, ClassNotFoundException{
                   String path = Paths.get("").toAbsolutePath().toString();
 FileInputStream fis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
            fis = new FileInputStream(path + "/" + StringUtil.getHexString(clientKeys.getEncoded())+".cer");
            System.out.println("read server cert");
            
            //ler array de certificados
            
            ObjectInputStream s = new ObjectInputStream(fis);
            
            fis.close();
            
            X509Certificate certClient[]= (X509Certificate[]) s.readObject();            
            //verifica as assinaturas
            try {
                certClient[0].verify(certClient[0].getPublicKey());
                System.out.println("Assinatura server-server válida.");
                 } catch (SignatureException ex) {
                System.out.println("Assinatura server-server NÃO válida.");
            } catch (CertificateException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchAlgorithmException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidKeyException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchProviderException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       }
            try{
                certClient[1].verify(certClient[0].getPublicKey());
                System.out.println("Assinatura server-client válida.");
                
            } catch (SignatureException ex) {
                System.out.println("Assinatura server-client NÃO válida.");
            } catch (CertificateException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchAlgorithmException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidKeyException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchProviderException ex) {
           Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
       }
    }

    public static void main(String[] args) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        FileInputStream fis = null;
        
        
            //GERA CERTIFICADO SERVER-SERVER
            /*keyUtils ku = new keyUtils();
            String path = Paths.get("").toAbsolutePath().toString();
            CertificateOps cops = new CertificateOps();
            try {
                cops.generateCertificate(ku.LoadKeyPairServer(path, "ECDSA"));
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
            }       catch (IOException ex) {
                        Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(CertificateOps.class.getName()).log(Level.SEVERE, null, ex);
                    }
            
            System.out.println("DONE!!!!");*/
            /*String path = Paths.get("").toAbsolutePath().toString();
            CertificateOps cops = new CertificateOps();
            keyUtils ku = new keyUtils();
            X509Certificate cert[] = cops.generateCertificateChain(clientKeys.getPublic());
            System.out.println("Certificate Created");*/

    }

}
