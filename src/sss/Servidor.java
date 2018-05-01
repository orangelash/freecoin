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
import static sss.VerifyChallenge.verify;

public class Servidor implements Runnable {

    public SecureRandom random = new SecureRandom();
    private int port = 9999;
    private boolean isServerDone = false;
    public static ArrayList<SSLSocket> clients = new ArrayList<SSLSocket>();
    public static ArrayList<String> desafioslista = new ArrayList<String>();

    public static void main(String[] args) {

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
            while (!isServerDone) {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                clients.add(sslSocket);
                ServerThread myRunnable3 = new ServerThread(sslSocket);
                Thread t3 = new Thread(myRunnable3);
                t3.start();

                ServerThreadEnvia myRunnable1 = new ServerThreadEnvia(sslSocket);
                Thread t1 = new Thread(myRunnable1);
                t1.start();

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

                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    String inetAddress = sslSocket.getInetAddress().getHostName();
                    String [] recebido= line.split("/");
                    if(recebido[0].equals("desafio"))
                    {
                        boolean res=verify(recebido[3],recebido[1],10);
                        if(res==true&&desafioslista.contains(recebido[1])){
                            desafioslista.remove(recebido[1]);
                            System.out.println("Parabens ganhas-te 1 freecoin bitch");
                            //AQUI FICA A PARTE DE DAR 1 FREECOIN AO UTILIZADOR
                        }
                    }
                    System.out.println("Inut : " + line + " ," + inetAddress);

                    if (line.trim().equals("007")) {
                        break;
                    }
                }
                // Write data
                sslSocket.close();
            } catch (Exception ex) {
                clients.remove(sslSocket);
                System.out.println("foi neste que rebentou 3");
                //APAGAR ESTE
                ex.printStackTrace();
            }
        }
    }

    static class ServerThreadEnvia implements Runnable {

        private SSLSocket sslSocket = null;

        ServerThreadEnvia(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
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
//exemoplio
                    /* printWriter.println("ola eu sou o server envia particular");
                    printWriter.flush();
                    sleep(60000);*/
                }

            } catch (Exception ex) {
                System.out.println("foi neste que rebentou 4");
                ex.printStackTrace();
            }
        }
    }

    static class ServerThreadEnviaAll implements Runnable {

        public ServerThreadEnviaAll() {
        }

        public String convertStringToHex(String str) {

            char[] chars = str.toCharArray();

            StringBuffer hex = new StringBuffer();
            for (int i = 0; i < chars.length; i++) {
                hex.append(Integer.toHexString((int) chars[i]));
            }

            return hex.toString();
        }

        public void run() {
            while (true) {
                String k = rand.randomnumber();
                desafioslista.add(convertStringToHex(k));
                for (int i = 0; i < clients.size(); i++) {
                    clients.get(i).setEnabledCipherSuites(clients.get(i).getSupportedCipherSuites());
                    try {
                        // Start handshake

                        clients.get(i).startHandshake();

                        // Get session after the connection is established
                        // SSLSession sslSession = clients.get(i).getSession();
                        OutputStream outputStream = clients.get(i).getOutputStream();

                        System.out.println(k);
                        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                        printWriter.println(k);
                        printWriter.flush();
                        // Write data
                        // clients.get(i).close();
                    } catch (Exception ex) {
                        System.out.println("foi neste que rebentou 66");
                        ex.printStackTrace();
                    }
                }
                try {
                    sleep(30000);

                } catch (InterruptedException ex) {
                    Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            //stop();
        }
    }

}
