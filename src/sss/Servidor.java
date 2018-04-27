package sss;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import static java.lang.Thread.sleep;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class Servidor implements Runnable {

    public SecureRandom random = new SecureRandom();
    private int port = 9999;
    private boolean isServerDone = false;
    public static ArrayList<SSLSocket> clients=new ArrayList<SSLSocket>();

    public static void main(String[] args) {
        
        System.out.println("quantas vezes?");
        ServerThreadEnviaAll myRunnable = new ServerThreadEnviaAll();
        Thread t = new Thread(myRunnable);
        t.start();
        Servidor servidor = new Servidor();
        servidor.run();
        

    }

    Servidor() {
        //clients = new ArrayList<SSLSocket>();

    }

    Servidor(int port) {
        this.port = port;
        /*ServerThreadEnviaAll myRunnable = new ServerThreadEnviaAll();
        Thread t = new Thread(myRunnable);
        t.start();*/
        // new ServerThreadEnviaAll(clients).start();
    }

    // Create the and initialize the SSLContext
    private SSLContext createSSLContext() {
        System.out.println("3");
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
            System.out.println("foi neste que rebentou 1");
            ex.printStackTrace();
        }

        return null;
    }

    // Start to run the server
    public void run() {
        SSLContext sslContext = this.createSSLContext();

        try {
            // Create server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

            // Create server socket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);

            System.out.println("SSL server started");
            System.out.println("333");
            while (!isServerDone) {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                clients.add(sslSocket);
                System.out.println("33333");
                // Start the server thread
                ServerThread myRunnable3 = new ServerThread(sslSocket);
                Thread t3 = new Thread(myRunnable3);
                t3.start();
                //new ServerThread(sslSocket).start();
                System.out.println("3333");
                //String k = new BigInteger(400, random).toString(32);
                //new ServerThreadEnvia(sslSocket, clients).start();
                ServerThreadEnvia myRunnable1 = new ServerThreadEnvia(sslSocket);
                Thread t1 = new Thread(myRunnable1);
                t1.start();
                System.out.println("vou para o all");

            }
        } catch (Exception ex) {
            System.out.println("foi neste que rebentou 2");
            ex.printStackTrace();
        }
    }

    // Thread handling the socket from client
    static class ServerThread implements Runnable {

        private SSLSocket sslSocket = null;

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            System.out.println("333");
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try {
                // Start handshake
                sslSocket.startHandshake();

                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();

                System.out.println("SSLSession :");
                System.out.println("\tProtocol : " + sslSession.getProtocol());
                System.out.println("\tCipher suite : " + sslSession.getCipherSuite());

                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                System.out.println("1");
                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    System.out.println("2");
                    String inetAddress = sslSocket.getInetAddress().getHostName();
                    System.out.println("Inut : " + line + " ," + inetAddress);

                    if (line.trim().equals("007")) {
                        break;
                    }
                }
                System.out.println("3");
                // Write data
                sslSocket.close();
            } catch (Exception ex) {

                System.out.println("foi neste que rebentou 3");
                ex.printStackTrace();
            }
        }
    }

    static class ServerThreadEnvia implements Runnable {

        private SSLSocket sslSocket = null;
       // public SecureRandom random = new SecureRandom();
        //List<SSLSocket> clients;

        ServerThreadEnvia(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
            //this.clients = clients;
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
                System.out.println("estou aqui 1");

                while (true) {

                    printWriter.println("ola eu sou o server envia particular");
                    printWriter.flush();
                    sleep(60000);
                }

            } catch (Exception ex) {
                System.out.println("foi neste que rebentou 4");
                ex.printStackTrace();
            }
        }
    }

    static class ServerThreadEnviaAll implements Runnable {

        // private List<SSLSocket> clients = null;
        //private String k = null;
        public ServerThreadEnviaAll() {
            System.out.println("eiii");
            // this.clients = clients;
            // this.k = k;
            //String k = new BigInteger(400, random).toString(32);
        }

        public void run() {
            System.out.println("all");
            while (true) {
                System.out.println("ola malta");
               // if() 
               String k = rand.randomnumber();
                for (int i = 0; i < clients.size(); i++) {
                    System.out.println("ola malta2");
                    clients.get(i).setEnabledCipherSuites(clients.get(i).getSupportedCipherSuites());
                    System.out.println("ola malta3");
                    try {
                        // Start handshake
                        System.out.println("ola malta4");
                        clients.get(i).startHandshake();

                       
                        // Get session after the connection is established
                        // SSLSession sslSession = clients.get(i).getSession();
                        OutputStream outputStream = clients.get(i).getOutputStream();

                        System.out.println(k);
                        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                        printWriter.println(k);
                        printWriter.flush();
                        // Write data
                           //clients.get(i).close();
                    } catch (Exception ex) {
                        System.out.println("foi neste que rebentou 66");
                        ex.printStackTrace();
                    }
                }
                try {
                    sleep(3000);
                } catch (InterruptedException ex) {
                    Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            //stop();
        }
    }

}
