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


/**
 *
 * @author Asus
 */
public class VerifyChallenge {

    public static String hexToBinary(String hex) {
        byte[] b = new BigInteger(hex, 16).toByteArray();
        String s1 = "";
        for (int i = 0; i < b.length; i++) {
            byte b1 = b[i];
            s1 = s1 + String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');

        }

      
        return s1;
    }

    public static Boolean verify(String hexaV, String hexaD, int bits) throws NoSuchAlgorithmException {
        String binarioV = hexToBinary(hexaV);
        String binarioD = hexToBinary(hexaD);
        System.out.println(binarioV);
        System.out.println(binarioD);
        String[] arys1 = binarioV.split("");
        String[] arys2 = binarioD.split("");
        for (int i = 0; i < bits; i++) {
            if (!arys1[i].equals(arys2[i])) {
                return false;
            }

        }

        return true;
    }

}
