/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.xml.bind.DatatypeConverter;
import static sss.Challange.previousHash;

/**
 *
 * @author Asus
 */
public class VerifyChallenge {

    public static String hexToBinary(String hex) {
        int i = Integer.parseInt(hex, 16);
        String bin = Integer.toBinaryString(i);
        return bin;
    }

    public static Boolean verify(String hexaV, String hexaD, int bits) throws NoSuchAlgorithmException {
        String binarioV = hexToBinary(hexaV);
        String binarioD = hexToBinary(hexaD);
        String[] arys1 = binarioV.split("");
        String[] arys2 = binarioD.split("");
        for (int i = 0; i <= bits; i++) {
            if (!arys1[i].equals(arys2[i])) {
                return false;
            }

        }

        return true;
    }

}
