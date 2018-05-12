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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
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
import static sss.Cliente.ClientThreadEscuta.respostaDesafio;

public class Cliente {

    private final BlockingQueue<String> queue;
    private static String desafio = "";
    private static String bitss = "";
    private static int leu = 0;
    private String host = "192.168.137.1";
    private int port = 9999;
    private static X509Certificate certi = null;
    static Session s;

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
        static byte[] respostaDesafio;

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
                ObjectInputStream fromClient;
                fromClient = new ObjectInputStream(sslSocket.getInputStream());
                ObjectOutputStream toServer = new ObjectOutputStream(sslSocket.getOutputStream());
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                while (true) {
                    String line = null;
                    //System.out.println("1");
                    //  while (!bufferedReader.readLine().isEmpty()) {
                    line = bufferedReader.readLine();
                    //System.out.println("2");
                    String[] server = line.split("//");
                    //System.out.println("3");
                    if (server[0].equals("desafio")) {
                        desafio = server[1];
                        bitss = server[2];
                        leu = 1;

                    } else if (server[0].equals("desafiowin")) {
                        System.out.println(server[1]);
                    } else if (server[0].equals("cadeia")) {
                        System.out.println("cadeia= " + server[1]);
                        /*byte[] byteArr = server[1].getBytes();
                        byte[] cadeia = Base64.getDecoder().decode(server[1]);
                        System.out.println(byteArr);
                        System.out.println("aqui: " + server[1].getBytes(StandardCharsets.UTF_8));*/

                        X509Certificate cert = (X509Certificate) fromClient.readObject();
                        System.out.println(cert);
                        certi = cert;

                        //keyUtils.bytesToHex(server[1]);
                    } else if (server[0].equals("respostaDesafio")) {
                        ////////VARIAVEIS
                        String path = Paths.get("").toAbsolutePath().toString();
                        KeyPair clienteKeys = keyUtils.LoadKeyPair(path, "ECDSA");
                        byte[] sign = StringUtil.applyECDSASig(clienteKeys.getPrivate(), server[1]);
                        toServer.writeObject(sign);

                        System.out.println("" + Arrays.toString(sign));
                        respostaDesafio = (byte[]) fromClient.readObject();
                        System.out.println("" + Arrays.toString(respostaDesafio));
                    }else if(server[0].equals("Montante")){
                        System.out.println("O seu saldo é: "+server[1]);
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
                    if (!desafio.equals("") && leu == 1) {
                        leu = 0;
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
                                    //leu=0;
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

                    System.out.println("-----BEM-VINDO AO FR€€COIN-----\n1-Registar\n2-Entrar\n0-Sair");
                    opc = Ler.umInt();
                    switch (opc) {
                        case 1: {
                            System.out.println("---- Registo ----");
                            int registoNovo = 1;
                            String path = Paths.get("").toAbsolutePath().toString();
                            //verificar se já tem chaves criadas
                            try {
                                //caso já tenha  perguntar se quer realmente registar-se outra vez
                                if (Files.exists(Paths.get(path + "/public.key"))) {
                                    System.out.println("Já tem um registo efetuado, deseja realmente efetuar um novo?\n1-Sim\n0-Não");
                                    registoNovo = Ler.umInt();
                                }

                            } catch (Exception e) {
                                //NÃO HÁ CHAVES
                            }

                            // caso não tenha chaves, registar-se
                            if (registoNovo == 1) {
                                System.out.println("----- Gerando chaves -----");
                                KeyPair novasChaves = keyUtils.generateKeyPairPrime192();
                                keyUtils.SaveKeyPair(path, novasChaves);
                                System.out.println("----- CHAVES -----");
                                keyUtils.dumpKeyPair(novasChaves);

                                //FAZER LIGAÇÃO COM O SERVIDOR, ENVIAR A PUBLIC KEY CIFRADA COM PUBLIC KEY DO SERVER
                                // 1 - LER CERTIFICADO OU PUBLIC KEY DO SERVIDOR
                                PublicKey server = keyUtils.LoadServerPublicKey(path, "ECDSA");

                                byte[] publicKeyX = novasChaves.getPublic().getEncoded();
                                String encodedPublicKeyX = Base64.getEncoder().encodeToString(publicKeyX);
                                printWriter.println("registar//" + encodedPublicKeyX); //VERIFICAR ISTO, ESTÁ A ENVAIR UMA PUBLIC KEY
                                printWriter.flush();

                                // 4 - ESCREVER CERTIFICADO 
                                sleep(2000);
                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                try {
                                    certi.verify(server);
                                    System.out.println("verificado");
                                    FileOutputStream fout = new FileOutputStream(path + "/meu.cer");
                                    fout.write(certi.getEncoded());
                                    fout.close();
                                } catch (Exception e) {
                                    //e.printStackTrace();
                                    System.out.println("nao verificado");
                                }
                                //X509Certificate certificate = CertOps.convertToX509Cert(certi);
                                //System.out.println("ei jude"+certificate);
                            }

                            break;
                        }
                        case 2: {
                            boolean continua = false;
                            System.out.println("entrar");
                            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                            String path = Paths.get("").toAbsolutePath().toString();

                            KeyPair clienteKeys = keyUtils.LoadKeyPair(path, "ECDSA");
                            PublicKey server = keyUtils.LoadServerPublicKey(path, "ECDSA");

                            // 1 - Enviar public key ao servidor, ele verifica se está registado
                            byte[] publicKeyX = clienteKeys.getPublic().getEncoded();
                            String encodedPublicKeyX = Base64.getEncoder().encodeToString(publicKeyX);
                            printWriter.println("login//" + encodedPublicKeyX); //VERIFICAR ISTO, ESTÁ A ENVAIR UMA PUBLIC KEY
                            printWriter.flush();

                            // 2 - Fazer autenticação mutua (AMBOS TÊM CERTIFICADOS UM DO OUTRO)
                            SecureRandom random = new SecureRandom();

                            int max = 500;
                            int min = 10;

                            int aux = random.nextInt(max - min + 1) + min;

                            RandomString desafio = new RandomString(aux);
                            String desafioEnviado = desafio.nextString();
                            printWriter.println("authDesafio//" + desafioEnviado);
                            printWriter.flush();
                            //  2.1) Ler certificados, ver se estão corretos, assinar um desafio recebido e enviar
                            sleep(1000);
                            try {
                                if (StringUtil.verifyECDSASig(server, desafioEnviado, respostaDesafio)) {
                                    System.out.println("Desafio correto, servidor autenticado.");
                                    continua = true;
                                } else {
                                    System.out.println("Desafio incorreto, servidor não autenticado.");
                                    continua = false;
                                }
                            } catch (Exception e) {
                                System.out.println("Desafio incorreto, servidor não autenticado.");
                                continua = false;
                            }
                            //  2.2) ver se o desafio que o servidor assinou está correto com o certificado dele, se sim, continuar, caso contrário aborta
                            // 3 - Gerar chaves de sessão
                            if (continua == true) {
                                new ClientThread(sslSocket, queue).start();
                                byte[] sessionKey = keyUtils.doECDH(clienteKeys.getPrivate(), server);
                                System.out.println("Chave de Sessão: " + keyUtils.bytesToHex(sessionKey));
                                byte[] sessionKeyA = new byte[sessionKey.length + 1];
                                byte[] sessionKeyB = new byte[sessionKey.length + 1];
                                byte[] sessionKeyC = new byte[sessionKey.length + 1];
                                byte[] sessionKeyD = new byte[sessionKey.length + 1];
                                sessionKeyA = Arrays.copyOf(sessionKey, sessionKey.length);
                                sessionKeyA[sessionKeyA.length - 1] = 65;
                                sessionKeyB = Arrays.copyOf(sessionKey, sessionKey.length);
                                sessionKeyB[sessionKeyA.length - 1] = 66;
                                sessionKeyC = Arrays.copyOf(sessionKey, sessionKey.length);
                                sessionKeyC[sessionKeyA.length - 1] = 67;
                                sessionKeyD = Arrays.copyOf(sessionKey, sessionKey.length);
                                sessionKeyD[sessionKeyA.length - 1] = 68;

                                MessageDigest digest;
                                digest = MessageDigest.getInstance("SHA-256");
                                byte[] hash = digest.digest(sessionKeyA);
                                String chaveA = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyB);
                                String chaveB = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyC);
                                String chaveC = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyD);
                                String chaveD = DatatypeConverter.printHexBinary(hash);
                                s = new Session(chaveA, chaveB, chaveC, chaveD, sslSocket, clienteKeys.getPublic());
                                int opc2 = 0;
                                do {

                                    System.out.println("-----BEM-VINDO AO FR€€COIN-----\n1-Fazer Transação\n2-Consultar Transações Associadas \n0-Sair");
                                    opc2 = Ler.umInt();
                                    switch (opc2) {
                                        case 1: {
                                            printWriter.println("transacao//.");
                                            printWriter.flush();
                                            PublicKey pubAlice = null;
                                            PrivateKey privateKeyAlice = null;
                                            try {
                                                //KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
                                                // X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyRecberByte);
                                                //publicKey = keyFactory.generatePublic(publicKeySpec);
                                                //pubAlice = LoadAlicePublicKey(path,"ECDSA");
                                                KeyPair alice = keyUtils.LoadKeyPair(path, "ECDSA");
                                                privateKeyAlice = alice.getPrivate();
                                                pubAlice = alice.getPublic();
                                            } catch (Exception e) {
                                                System.out.println("rebentei todo");
                                            }

                                            System.out.println("Insira o valor a transferir");
                                            float valorEnviar = Ler.umFloat();

                                            PublicKey destinatario = null;
                                            do {
                                                System.out.println("Insira o caminho da chave publica do destinatário");
                                                String pasta = Ler.umaString();
                                                try {
                                                    destinatario = keyUtils.LoadAlicePublicKey(pasta, "ECDSA");
                                                } catch (Exception e) {
                                                    System.out.println("deu aqui");
                                                }
                                            } while (destinatario == null);
                                            Transaction transacao = new Transaction(pubAlice, destinatario, valorEnviar);
                                            transacao.generateSignature(privateKeyAlice);
                                            System.out.println("Transacao => " + transacao.toString());
                                            ObjectOutputStream toServer;
                                            toServer = new ObjectOutputStream(sslSocket.getOutputStream());
                                            toServer.writeObject(transacao);
                                            break;
                                        }
                                        case 2:
                                            printWriter.println("Montante//");
                                            printWriter.flush();
                                            break;
                                           
                                        case 0: {
                                            printWriter.println("LogOut//.");
                                            printWriter.flush();
                                            break;
                                        }
                                    }
                                } while (opc2 != 0);

                            }

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
