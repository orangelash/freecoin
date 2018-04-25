/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sad;
import java.security.*;
import java.security.spec.*;

public class ECCKeyGeneration {
  public static void main(String[] args) throws Exception {
    KeyPairGenerator kpg;
    kpg = KeyPairGenerator.getInstance("EC","SunEC");
    ECGenParameterSpec ecsp;
    ecsp = new ECGenParameterSpec("secp192r1");
    kpg.initialize(ecsp);

    KeyPair kp = kpg.genKeyPair();
    PrivateKey privKey = kp.getPrivate();
    PublicKey pubKey = kp.getPublic();

    System.out.println(privKey.toString());
    System.out.println(pubKey.toString());
  }
}