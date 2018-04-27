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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class Cliente {

    private final BlockingQueue<String> queue;

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

            System.out.println("SSL client started");
            new ClientThread(sslSocket, queue).start();
            new ClientThreadEnvia(sslSocket, queue).start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket to server
    static class ClientThread extends Thread {

        private final BlockingQueue<String> queue;
        public SSLSocket sslSocket = null;

        ClientThread(SSLSocket sslSocket, BlockingQueue<String> q) {
            this.sslSocket = sslSocket;
            queue = q;
        }

        public void run() {
             sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
         //    sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
 
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
                     System.out.println("aqui");
 
                     //line = bufferedReader.readLine();
                     //System.out.println("oi");
                     System.out.println("aquii");
                   //  while (!bufferedReader.readLine().isEmpty()) {
                         System.out.println("aquiii");
                         line = bufferedReader.readLine();
                         System.out.println("Mensagem do Servidor : " + line);
                         queue.put(line);
                         
 
                   //  }
                     System.out.println("passei");
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
                     sleep(300);
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
                            System.out.println(value);

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
