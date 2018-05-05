/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

/**
 *
 * @author Asus
 */
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;

public class Cliente {

    private final BlockingQueue<String> queue;
    private static String desafio = "";
    private static String bitss = "";
    private String host = "192.168.137.1";
    private int port = 9999;

    public static void main(String[] args) {
        BlockingQueue<String> q = new LinkedBlockingQueue<String>();
        Cliente clientRecebe = new Cliente(q);
        clientRecebe.run();
    }
    public static int enviarecebe = 0;

    Cliente(BlockingQueue<String> q) {
        queue = q;
    }

    Cliente(String host, int port, BlockingQueue<String> q) {
        this.host = host;
        this.port = port;
        queue = q;
    }

    // Create the and initialize the SSLContext
    private SSLContext createSSLContext() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);

            keyStore.store(new FileOutputStream("test.jks"), "7QwRU3LQ7UfaGJ+mRgqmde/jeQ+ncR9X+s7BxTGqJ8k=".toCharArray());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("test.jks"), "7QwRU3LQ7UfaGJ+mRgqmde/jeQ+ncR9X+s7BxTGqJ8k=".toCharArray());

            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "7QwRU3LQ7UfaGJ+mRgqmde/jeQ+ncR9X+s7BxTGqJ8k=".toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km, tm, null);

            return sslContext;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    // Start to run the server
    public void run() {
        SSLContext sslContext = this.createSSLContext();

        try {
            // Create socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create socket
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);

            new ClientThread(sslSocket, queue).start();
            new ClientThreadEnvia(sslSocket, queue).start();
            new ClientThreadEscuta(sslSocket, queue).start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket to server
    static class ClientThreadEscuta extends Thread {

        public static String hash;
        public static String previousHash;
        private static String data; //our data will be a simple message.
        private static long timeStamp; //as number of milliseconds since 1/1/1970.
        private static int nonce;
        private final BlockingQueue<String> queue;
        public SSLSocket sslSocket = null;
        // private static int bits=15;

        ClientThreadEscuta(SSLSocket sslSocket, BlockingQueue<String> q) {
            this.sslSocket = sslSocket;
            queue = q;
        }

        public void run() {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                while (true) {
                    String line = null;
                    System.out.println("1");
                    //  while (!bufferedReader.readLine().isEmpty()) {
                    line = bufferedReader.readLine();
                    System.out.println("2");
                    String[] server = line.split("//");
                    System.out.println("3");
                    if (server[0].equals("desafio")) {
                        desafio = server[1];
                        bitss = server[2];

                    } else if (server[0].equals("desafiowin")) {
                        System.out.println(server[1]);
                    }
                }

                // sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }

        }

    }

    static class ClientThread extends Thread {

        public static String hash;
        public static String previousHash;
        private static String data; //our data will be a simple message.
        private static long timeStamp; //as number of milliseconds since 1/1/1970.
        private static int nonce;
        private final BlockingQueue<String> queue;
        public SSLSocket sslSocket = null;
        // private static int bits=15;

        ClientThread(SSLSocket sslSocket, BlockingQueue<String> q) {
            this.sslSocket = sslSocket;
            queue = q;
        }

        public void run() {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                while (true) {
                    sleep(10);
                    if (!desafio.equals("")) {
                        int bits = Integer.parseInt(bitss);
                        System.out.println("Novo desafio: " + desafio);
                        SecureRandom random = new SecureRandom();
                        String k = new BigInteger(400, random).toString(32);
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(desafio.getBytes(StandardCharsets.UTF_8));
                        String hex = DatatypeConverter.printHexBinary(hash);

                        int foudIt = 0;

                        while (foudIt == 0) {
                            nonce++;
                            String calculatehash = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
                            byte[] hashdes = digest.digest(calculatehash.getBytes(StandardCharsets.UTF_8));
                            previousHash = DatatypeConverter.printHexBinary(hashdes);
                            String s1 = "";
                            String s2 = "";
                            int flag = 0;
                            int count = 0;

                            //  if (bufferedReader.ready()) {
                            // line = bufferedReader.readLine();

                            /* String[] para = line.split("//");
                            if (para[0].equals("desafio") && para[1].equals("para")) {
                                System.out.println("ola!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                                /* printWriter.println("desafio/para");
                                printWriter.flush();*/
 /*break;
                            }*/
                            //  }
                            // System.out.println("tentando");
                            for (int i = 0; i <= bits; i++) {
                                byte b1 = hash[i];
                                byte b2 = hashdes[i];
                                s1 = String.format("%8s", Integer.toBinaryString(b2 & 0xFF)).replace(' ', '0');
                                s2 = String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
                                String[] arys1 = s1.split("");
                                String[] arys2 = s2.split("");
                                for (int j = 0; j < arys1.length; j++) {
                                    if (!arys1[j].equals(arys2[j])) {
                                        if (count >= bits) {
                                            break;
                                        } else {
                                            flag = 1;
                                            break;
                                        }

                                    }
                                    count++;

                                }

                                if (count >= bits && flag == 0) {
                                    System.out.println("encontrei");
                                    foudIt = 1;
                                    break;
                                }
                                if (flag == 1) {
                                    break;
                                }

                            }
                            if (count >= bits && flag == 0) {
                                String hashsolved = previousHash;
                                System.out.println(hashsolved);
                                printWriter.println("desafio//" + desafio + "//" + bitss + "//resolvido//" + hashsolved + "/" + sslSocket.getLocalAddress());
                                printWriter.flush();
                            }
                            //queue.put(hashsolved);
                        }

                        //  }
                        String value = "";
                        if (!queue.isEmpty()) {
                            while (!queue.isEmpty()) {
                                value = queue.take();
                                if (value.equals('0')) {
                                    sslSocket.close();
                                    break;

                                }

                            }
                        }
                        //sleep(300);
                    }
                }
                // sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    static class ClientThreadEnvia extends Thread {

        public SSLSocket sslSocket = null;
        private final BlockingQueue<String> queue;

        ClientThreadEnvia(SSLSocket sslSocket, BlockingQueue<String> q) {
            this.sslSocket = sslSocket;
            queue = q;
        }

        public void run() {
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                int opc = 0;
                do {
                    String value = "";
                    if (!queue.isEmpty()) {
                        while (!queue.isEmpty()) {
                            value = queue.take();
                            printWriter.println("desafio//" + value + "//" + sslSocket.getLocalAddress());
                            printWriter.flush();

                        }
                    }

                    System.out.println("-----BEM-VINDO AO FR€COIN-----\n1-Registar\n2-Entrar\n0-Sair");
                    opc = Ler.umInt();
                    switch (opc) {
                        case 1: {
                            System.out.println("registo");
                            String aux = Ler.umaString();
                            printWriter.println(aux);
                            printWriter.flush();
                            break;
                        }
                        case 2: {
                            System.out.println("entrar");
                            break;
                        }

                        case 0:
                            System.exit(0);
                            break;
                        default:
                            System.out.println("Opção inválida, tente novamente!\n");
                    }
                    if (!queue.isEmpty()) {
                        while (!queue.isEmpty()) {
                            value = queue.take();
                            System.out.println(value);
                        }
                    }

                } while (opc != 0);

                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}
