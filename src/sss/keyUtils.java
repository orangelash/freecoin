/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


 
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


/**
 *
 * @author Vasco Lopes
 */
public class keyUtils {

    public static KeyPair generateKeyPairPrime192() {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
            // Initialize the key generator and generate a KeyPair
            keyGen.initialize(ecSpec, random); //256 
            KeyPair keyPair = keyGen.generateKeyPair();

            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    public static KeyPair LoadKeyPair(String path, String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static void dumpKeyPair(KeyPair keyPair) {
        PublicKey pub = keyPair.getPublic();
        System.out.println("Public Key: " + StringUtil.getHexString(pub.getEncoded()));

        PrivateKey priv = keyPair.getPrivate();
        System.out.println("Private Key: " + StringUtil.getHexString(priv.getEncoded()));
    }

    public static KeyStore generateCertificate (KeyPair keypair, Key clientPrivateKey){
        try{
            //Generate ROOT server certificate
            CertAndKeyGen keyGenS=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            PrivateKey rootPrivateKey=keypair.getPrivate();
            X509Certificate rootCertificate = keyGenS.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);
             
            //Generate client certificate
            CertAndKeyGen keyGenC=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            X509Certificate clientCertificate = keyGenC.getSelfCertificate(new X500Name("CN=CLIENT"), (long) 365 * 24 * 60 * 60);
                          
            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            clientCertificate = createSignedCertificate(clientCertificate,rootCertificate,rootPrivateKey);
             
            X509Certificate[] chain = new X509Certificate[2];
            chain[0]=rootCertificate;
            chain[1]=clientCertificate;
            
            String alias = "mykey";
            char[] password = "password".toCharArray();
            String keystore = "testkeys.jks";
             
            //Store the certificate chain
            storeKeyAndCertificateChain(alias, password, keystore, clientPrivateKey, chain);
            //Reload the keystore and display key and certificate chain info
            loadAndDisplayChain(alias, password, keystore);
            //Clear the keystore
            clearKeyStore(alias, password, keystore);
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }

    private static void storeKeyAndCertificateChain(String alias, char[] password, String keystore, Key key, X509Certificate[] chain) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(null,null);
         
        keyStore.setKeyEntry(alias, key, password, chain);
        keyStore.store(new FileOutputStream(keystore),password);
    }
     
    private static void loadAndDisplayChain(String alias,char[] password, String keystore) throws Exception{
        //Reload the keystore
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore),password);
         
        Key key=keyStore.getKey(alias, password);
         
        if(key instanceof PrivateKey){
            System.out.println("Get private key : ");
            System.out.println(key.toString());
             
            Certificate[] certs=keyStore.getCertificateChain(alias);
            System.out.println("Certificate chain length : "+certs.length);
            for(Certificate cert:certs){
                System.out.println(cert.toString());
            }
        }else{
            System.out.println("Key is not private key");
        }
    }
     
    private static void clearKeyStore(String alias,char[] password, String keystore) throws Exception{
        KeyStore keyStore=KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(keystore),password);
        keyStore.deleteEntry(alias);
        keyStore.store(new FileOutputStream(keystore),password);
    }
     
    private static X509Certificate createSignedCertificate(X509Certificate certificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();
             
            byte[] inCertBytes = certificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName((X500Name) issuer));
             
            //No need to add the BasicContraint for leaf cert
            if(!certificate.getSubjectDN().getName().equals("CN=CLIENT")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }
             
            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);
             
            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
}

