package sss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import static sss.StringUtil.hexStringToByteArray;

public class AESEncryption {

    // private static final String TOKEN = "passwd";
    private String salt;
    private int pwdIterations = 65536;
    private int keySize = 128;
    private byte[] ivBytes;
    private String keyAlgorithm = "AES";
    private String encryptAlgorithm = "AES/CBC/PKCS5Padding";
    private String secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1";

    public AESEncryption() {
        this.salt = getSalt();
    }

    private String getSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String text = new String(bytes);
        return new Base64().encodeAsString(bytes);
    }

    public String getSalta() {

        return salt;
    }

    public String getIv() {
        return new Base64().encodeAsString(ivBytes);
    }

    /**
     *
     * @param plainText
     * @return encrypted text
     * @throws Exception
     */
    public String encyrpt(String plainText, String secKey) throws Exception {
        //generate key
        byte[] saltBytes = salt.getBytes();
         byte[] bytes=hexStringToByteArray(secKey);
       SecretKey originalKey = new SecretKeySpec(bytes, 0, 16, "AES");
        //AES initialization
 
        Cipher cipher = Cipher.getInstance(encryptAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, originalKey);

        //generate IV
        ivBytes = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedText = cipher.doFinal(plainText.getBytes());
        String s = new Base64().encodeAsString(encryptedText);

        return s;
    }

    /**
     *
     * @param encryptText
     * @return decrypted text
     * @throws Exception
     */
    public String decrypt(String encryptText, String secKey, byte[] salta, byte[] iv) throws Exception {
        byte[] saltBytes = salta;
        byte[] encryptTextBytes = new Base64().decode(encryptText);

        //decrypt the message
        byte[] bytes=hexStringToByteArray(secKey);
        //byte[] bytes = new BigInteger("7F" + secKey, 16).toByteArray();
        SecretKey originalKey = new SecretKeySpec(bytes, 0, 16, "AES");
        Cipher cipher = Cipher.getInstance(encryptAlgorithm);

        cipher.init(Cipher.DECRYPT_MODE, originalKey, new IvParameterSpec(iv));

        byte[] decyrptTextBytes = cipher.doFinal(encryptTextBytes);

        String text = new String(decyrptTextBytes);
        return text;
    }

}
