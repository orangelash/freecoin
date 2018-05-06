/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
//import org.bouncycastle.openssl.PEMWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.util.Base64;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import static org.bouncycastle.asn1.x509.X509Extensions.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 *
 * @author Guilherme
 */
public class CertOps {

    X509Certificate createCertificate(boolean isServer, PrivateKey sk, PublicKey pk) throws FileNotFoundException {
        Security.addProvider(new BouncyCastleProvider());
        String path = Paths.get("").toAbsolutePath().toString();

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        if (isServer) {
            certGen.setIssuerDN(new X509Name("CN=SERVER"));
            certGen.setSubjectDN(new X509Name("DC=SERVER"));
        } else {
            certGen.setIssuerDN(new X509Name("CN=SERVER"));
            certGen.setSubjectDN(new X509Name("DC=CLIENT" + StringUtil.getHexString(pk.getEncoded())));
        }

        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
        certGen.setPublicKey(pk);
        certGen.setSignatureAlgorithm("SHA256WithECDSA");

        try {
            X509Certificate cert = certGen.generate(sk, "BC");
            String path2 = "";
            if (isServer) {
                path2 = "/server.cer";

            } else {
                path2 = StringUtil.getHexString(pk.getEncoded()) + ".cer";
            }
            FileOutputStream fout = new FileOutputStream(path + path2);
            fout.write(cert.getEncoded());

            Writer wr = new OutputStreamWriter(fout, Charset.forName("UTF-8"));
            wr.write(new sun.misc.BASE64Encoder().encode(cert.getEncoded()));
            wr.flush();
            fout.close();

            if (!isServer) {
                return cert;
            }

        } catch (CertificateEncodingException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalStateException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    X509Certificate generateCertificateChain(PublicKey pk) throws InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        String path = Paths.get("").toAbsolutePath().toString();

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(path + "/server.cer");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();

            keyUtils ku = new keyUtils();
            KeyPair kp = ku.LoadKeyPairServer(path, "ECDSA");
            cert.verify(kp.getPublic());
            //X509Certificate[] certChain = {cert,createCertificate(false, kp.getPrivate(), pk)};

            X509Certificate certClient = createCertificate(false, kp.getPrivate(), pk);

            FileOutputStream fout = new FileOutputStream(path + "/" + StringUtil.getHexString(pk.getEncoded()) + ".cer");
            fout.write(cert.getEncoded());
            Writer wr = new OutputStreamWriter(fout, Charset.forName("UTF-8"));
            //wr.write("---BEGIN CERTIFICATE---" + DatatypeConverter.printBase64Binary(certChain[0].getEncoded()) + "---END CERTIFICATE---" + "\n" + "---BEGIN CERTIFICATE---" + DatatypeConverter.printBase64Binary(certChain[1].getEncoded()) + "---END CERTIFICATE---");
            wr.write("---BEGIN CERTIFICATE---" + DatatypeConverter.printBase64Binary(certClient.getEncoded()) + "---END CERTIFICATE---");
            wr.flush();
            fout.close();
            return certClient;

        } catch (CertificateException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private boolean verifyCert(X509Certificate cert, PublicKey pk) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String path = Paths.get("").toAbsolutePath().toString();
        try {
            cert.verify(pk);
        } catch (CertificateException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(CertOps.class.getName()).log(Level.SEVERE, null, ex);
        }
        return true;
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString.replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString);
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }
}
