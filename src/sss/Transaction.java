/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;



public class Transaction implements Serializable {
    public PublicKey senderPublicKey; //the one who gives the money
    public PublicKey receiverPublicKey; // the one to receive
    public float amount; // amount of freecoin to be sent
    public byte[] signatureSender; // signature of the sender
    public byte[] signatureServer; // signature of the server (confirms that the sender can send that money)

    public Transaction(PublicKey senderPublicKey, PublicKey receiverPublicKey, float amount) {
        this.senderPublicKey = senderPublicKey;
        this.receiverPublicKey = receiverPublicKey;
        this.amount = amount;
    }

    public Transaction() {
    }
    
    public boolean verifySignature() {
	String data = StringUtil.getStringFromKey(senderPublicKey) + StringUtil.getStringFromKey(receiverPublicKey) + Float.toString(amount);
	return StringUtil.verifyECDSASig(senderPublicKey, data, signatureSender);
    }
    
    /**
     * Generate Signature of the sender
     * @param privateKey 
     */
    public void generateSignature(PrivateKey privateKey) {
            String data = StringUtil.getStringFromKey(senderPublicKey) + StringUtil.getStringFromKey(receiverPublicKey) + Float.toString(amount);
            signatureSender = StringUtil.applyECDSASig(privateKey,data);		
    }
    /**
     * Generate Signature of the server
     * @param privateKey 
     */
    public void generateSignatureServer(PrivateKey privateKey) {
            String data = StringUtil.getStringFromKey(senderPublicKey) + StringUtil.getStringFromKey(receiverPublicKey) + Float.toString(amount);
            signatureServer = StringUtil.applyECDSASig(privateKey,data);		
    }
    
    public PublicKey getSenderPublicKey() {
        return senderPublicKey;
    }

    public void setSenderPublicKey(PublicKey senderPublicKey) {
        this.senderPublicKey = senderPublicKey;
    }

    public PublicKey getReceiverPublicKey() {
        return receiverPublicKey;
    }

    public void setReceiverPublicKey(PublicKey receiverPublicKey) {
        this.receiverPublicKey = receiverPublicKey;
    }

    public float getAmount() {
        return amount;
    }

    public void setAmount(float amount) {
        this.amount = amount;
    }

    public byte[] getSignatureSender() {
        return signatureSender;
    }

    public void setSignatureSender(byte[] signatureSender) {
        this.signatureSender = signatureSender;
    }

    public byte[] getSignatureServer() {
        return signatureServer;
    }

    public void setSignatureServer(byte[] signatureServer) {
        this.signatureServer = signatureServer;
    }

    @Override
    public String toString() {
        return "Transaction{" + "senderPublicKey=" + senderPublicKey + ", receiverPublicKey=" + receiverPublicKey + ", amount=" + amount + ", signatureSender=" + signatureSender + ", signatureServer=" + signatureServer + '}';
    }
    
    
}

