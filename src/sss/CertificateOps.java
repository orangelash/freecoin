/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.time.*;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.extension.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 *
 * @author pr3
 */
public class CertificateOps {

    private String createCert() throws IOException {
        Calendar startDate = Calendar.getInstance().getTime();                // time from which certificate is valid
        Calendar expiryDate = startDate.add(Calendar.DAY_OF_YEAR, 360);            // time after which certificate is not valid
        BigInteger serialNumber = ...;       // serial number for certificate
        PrivateKey caKey = ...;              // private key of the certifying authority (ca) certificate
        X509Certificate caCert = ...;        // public key certificate of the certifying authority
        KeyPair keyPair = ...;               // public/private key pair that we are creating certificate for
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(subjectName);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm(signatureAlgorithm);

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.getPublic());

        X509Certificate cert = certGen.generate(caKey, "BC");   // note: private key of CA
    }

    private String convertCertificateToPEM(X509Certificate signedCertificate) throws IOException {
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(signedCertificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

}
