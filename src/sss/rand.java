/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Asus
 */
public class rand {

    static int count = 0;

    public static String randomnumber() {
        SecureRandom random = new SecureRandom();
        String k = new BigInteger(400, random).toString(32);
       /* if (count!=0)
            System.out.println("Novo desafio enviado");
        count++;*/
        return k;

    }
}
