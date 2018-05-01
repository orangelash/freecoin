/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;

/**
 *
 * @author Vasco Lopes
 */
public class Registo {
    public static void main(String args[]) {
        try {
            String path = Paths.get("").toAbsolutePath().toString();
            try {
                KeyPair generatedKeyPair = keyUtils.generateKeyPairPrime192();

                System.out.println("Generated Key Pair");
                keyUtils.dumpKeyPair(generatedKeyPair);
                keyUtils.SaveKeyPair(path, generatedKeyPair);

                KeyPair loadedKeyPair = keyUtils.LoadKeyPair(path, "ECDSA");
                System.out.println("Loaded Key Pair");
                keyUtils.dumpKeyPair(loadedKeyPair);
                System.out.println(""+loadedKeyPair.getPublic().toString());

            } catch (Exception e) {
                System.out.println("lol :(");
            }

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }
}
