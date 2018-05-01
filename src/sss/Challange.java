/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;
/*
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
/*public class Challange {

    public static String hash;
    public static String previousHash;
    private static String data; //our data will be a simple message.
    private static long timeStamp; //as number of milliseconds since 1/1/1970.
    private static int nonce;

    public static String challengeSolve(String text, int bits) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        String k = new BigInteger(400, random).toString(32);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        String hex = DatatypeConverter.printHexBinary(hash);
        System.out.println("O hash do desafio: " + hex);
       /* String s1 = "";
        for (int i = 0; i < hash.length; i++) {
            byte b1 = hash[i];
            s1 = s1 + String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');

        }*/
      /*  int foudIt = 0;
        
      
        while (foudIt == 0) {
            nonce++;
            String calculatehash = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
            byte[] hashdes = digest.digest(calculatehash.getBytes(StandardCharsets.UTF_8));
            previousHash = DatatypeConverter.printHexBinary(hashdes);
            String s1 = "";
            String s2 = "";  
            int flag=0;
            int count=0;
           // System.out.println("tentando");
            for (int i = 0; i <= bits; i++) {
                byte b1 = hash[i];
                byte b2 = hashdes[i];
                s1=String.format("%8s", Integer.toBinaryString(b2 & 0xFF)).replace(' ', '0');
                s2=String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                String[] arys1 = s1.split("");
                String[] arys2 = s2.split("");
                System.out.println(s1);
                System.out.println(s2);
                for(int j=0;j<arys1.length;j++)
                {
                    if(!arys1[j].equals(arys2[j])){
                        System.out.println("nobrak");
                        if(count>=bits)
                            break;
                        else{
                            flag=1;
                            break;
                        }
                        
                    }
                    count++;
                        
                } 
               
                if(count>=bits &&flag==0){
                    System.out.println("encontrei");
                    foudIt=1;
                    break;
                }
                if(flag==1)
                    break;

            }

        }
        
     
        System.out.println("\n");

        return previousHash;
    }

  

}
*/