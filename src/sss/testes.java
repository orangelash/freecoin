/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 *
 * @author Vasco Lopes
 */
public class testes {

    public static PrivateKey privKey;
    public static PublicKey pubKey;
    public static PublicKey receiver;
    public static PrivateKey lixo;

    public static KeyPair generateKeyPair() {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
            // Initialize the key generator and generate a KeyPair
            keyGen.initialize(ecSpec, random); //256 
            KeyPair keyPair = keyGen.generateKeyPair();
            // Set the public and private keys from the keyPair
            privKey = keyPair.getPrivate();
            pubKey = keyPair.getPublic();
            receiver = keyPair.getPublic();
            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        generateKeyPair();
        Transaction x = new Transaction(pubKey, receiver, 2);
        x.generateSignature(privKey); //com "lixo" da false a verificação

        System.out.println("" + x.verifySignature());
        System.out.println("" + x.toString());
    }
}
