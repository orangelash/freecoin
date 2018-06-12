/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.security.PublicKey;
import javax.net.ssl.SSLSocket;


public class Session {

    public String chaveA; //cifrar cliente servidor
    public String chaveB; //cifrar servidor cliente
    public String chaveC;   //
    public String chaveD;
    public SSLSocket ssl;
    public PublicKey pk;

    public String getChaveA() {
        return chaveA;
    }

    public Session(SSLSocket ssl, PublicKey pk) {
        this.ssl = ssl;
        this.pk = pk;
    }

    public void setChaveA(String chaveA) {
        this.chaveA = chaveA;
    }

    public String getChaveB() {
        return chaveB;
    }

    public void setChaveB(String chaveB) {
        this.chaveB = chaveB;
    }

    public String getChaveC() {
        return chaveC;
    }

    public void setChaveC(String chaveC) {
        this.chaveC = chaveC;
    }

    public String getChaveD() {
        return chaveD;
    }

    public void setChaveD(String chaveD) {
        this.chaveD = chaveD;
    }

    public SSLSocket getSsl() {
        return ssl;
    }

    public void setSsl(SSLSocket ssl) {
        this.ssl = ssl;
    }

    public PublicKey getPk() {
        return pk;
    }

    public void setPk(PublicKey pk) {
        this.pk = pk;
    }

    public Session() {
    }

    public Session(String chaveA, String chaveB, String chaveC, String chaveD, SSLSocket ssl, PublicKey pk) {
        this.chaveA = chaveA;
        this.chaveB = chaveB;
        this.chaveC = chaveC;
        this.chaveD = chaveD;
        this.ssl = ssl;
        this.pk = pk;
    }
}
