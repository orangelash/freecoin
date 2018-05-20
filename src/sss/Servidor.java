package sss;

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
import static java.lang.Thread.sleep;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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
import javax.xml.bind.DatatypeConverter;
import static sss.VerifyChallenge.verify;

public class Servidor implements Runnable {

    public SecureRandom random = new SecureRandom();
    private int port = 9999;
    private boolean isServerDone = false;
    public static ArrayList<SSLSocket> clients = new ArrayList<SSLSocket>();
    public static ArrayList<SSLSocket> clientsRes = new ArrayList<SSLSocket>();
    public static ArrayList<String> desafioslista = new ArrayList<String>();
    public static boolean estado = false;
    public static String quemresolveu = null;
    public static int bits = 22;
    static long startTime = 0;
    static long endTime = 0;
    static long time = 30000;
    static int flag2 = 0;
    public static ArrayList<Session> sess = new ArrayList<Session>();
    public static ObjectOutputStream toServer;
    public static ObjectInputStream fromClient;
    //public static ArrayList<Transaction> transacoes = new ArrayList<>();

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
//                Transaction transferir = new Transaction(null,null, (float) 0.0);
//                ArrayList<Transaction> transacoes = new ArrayList<Transaction>();
//                transacoes.add(transferir);
//                FileOutputStream fout = new FileOutputStream("transacoes.txt");
//                ObjectOutputStream oos = new ObjectOutputStream(fout);
//                oos.writeObject(transacoes);
//                oos.close();
//                fout.close();
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

                ServerThread myRunnable3 = new ServerThread(sslSocket);
                Thread t3 = new Thread(myRunnable3);
                t3.start();

                //ServerThreadEnvia myRunnable1 = new ServerThreadEnvia(sslSocket);
                //Thread t1 = new Thread(myRunnable1);
                //  t1.start();
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
            Session p;
            try {
                // Start handshake
                sslSocket.startHandshake();
                toServer = new ObjectOutputStream(sslSocket.getOutputStream());
                fromClient = new ObjectInputStream(sslSocket.getInputStream());
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
                String path = Paths.get("").toAbsolutePath().toString();
                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    String inetAddress = sslSocket.getInetAddress().getHostName();
                    System.out.println(line);
                    String[] recebido = line.split("//");
                    if (recebido[0].equals("desafio")) {

                        Session r = new Session();
                        for (int i = 0; i < sess.size(); i++) {
                            if (sess.get(i).getSsl() == sslSocket) {
                                r = sess.get(i);
                            }
                        }
                        //import org.apache.commons.codec.binary.Base64;
                        System.out.println("ENCRIPTADO: " + recebido[1]);
                        AESEncryption e = new AESEncryption();
                        byte[] salt = new org.apache.commons.codec.binary.Base64().decode(recebido[2]);
                        byte[] iv = new org.apache.commons.codec.binary.Base64().decode(recebido[3]);
                        System.out.println("recebi o salt: " + recebido[2] + "revebi o iv: " + recebido[3] + " recebi o tamanho do iv: " + recebido[3].length() + " a chave a usar: " + r.getChaveA() + "cripto: " + recebido[1]);

                        String texto = e.decrypt(recebido[1], r.getChaveA(), salt, iv);
                        String[] part = texto.split("//");
                        System.out.println("" + texto);

                        MessageDigest digest;
                        try {
                            digest = MessageDigest.getInstance("SHA-256");
                            byte[] hash = digest.digest(part[0].getBytes(StandardCharsets.UTF_8));
                            String hex = DatatypeConverter.printHexBinary(hash);
                            String desafio = hex;
                            String desafioSolved = part[3];

                            boolean res = verify(desafioSolved, desafio, bits);
                            if (res == true && desafioslista.contains(desafio)) {

                                String envia = "Desafio resolvido, ganhou uma freecoin";
                                AESEncryption es = new AESEncryption();
                                Session ra = new Session();
                                for (int i = 0; i < sess.size(); i++) {
                                    if (sess.get(i).getSsl() == sslSocket) {
                                        ra = sess.get(i);
                                    }
                                }
                                envia = es.encyrpt(envia, ra.getChaveB());
                                String toCalcMac = "desafiowin//" + envia + "//" + es.getSalta() + "//" + es.getIv();
                                String MAC = Base64.getEncoder().encodeToString(StringUtil.generateHMac(toCalcMac, ra.getChaveD()));
                                printWriter.println("desafiowin//" + envia + "//" + es.getSalta() + "//" + es.getIv() + "//" + MAC);
                                printWriter.flush();

                                /*  printWriter.println("desafiowin//Desafio resolvido, ganhou uma freecoin");
                                printWriter.flush();*/
                                estado = true;
                                quemresolveu = sslSocket.getInetAddress().getHostAddress();

                                desafioslista.remove(desafio);
                                System.out.println("Parabens ganhas-te 1 freecoin bitch");
                                flag2 = 0;
                                clientsRes.add(sslSocket);
                                //AQUI FICA A PARTE DE DAR 1 FREECOIN AO UTILIZADOR
                                Session r2 = new Session();
                                for (int i = 0; i < sess.size(); i++) {
                                    if (sess.get(i).getSsl() == sslSocket) {
                                        r2 = sess.get(i);
                                    }
                                }

                                PublicKey receiver = r.getPk();
                                KeyPair servidor = keyUtils.LoadKeyPairServer(path, "ECDSA");
                                Transaction transferir = new Transaction(servidor.getPublic(), receiver, 1);
                                PrivateKey servidor2 = servidor.getPrivate();
                                transferir.generateSignatureServer(servidor2);
                                //synchronized (transacoes) {
                                System.out.println("pega lá mano");
                                transferir.generateSignatureServer(servidor2);
                                ArrayList<Transaction> transacoes = new ArrayList<Transaction>();
                                ObjectInputStream ob = new ObjectInputStream(new FileInputStream("transacoes.txt"));
                                transacoes = (ArrayList<Transaction>) ob.readObject();
                                transacoes.add(transferir);
                                ob.close();
                                for (int i = 0; i < transacoes.size(); i++) {
                                    System.out.println(transacoes.get(i));
                                }
                                ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("transacoes.txt"));
                                oos.writeObject(transacoes);
                                oos.close();

                                // }
                            } else if (res == true) {
                                clientsRes.add(sslSocket);
                            }

                            if (clientsRes.size() == clients.size()) {
                                endTime = System.currentTimeMillis();
                                time = endTime - startTime;
                                endTime = 0;
                                startTime = 0;
                                System.out.println("o tempo foi de: " + time);
                            }
                        } catch (NoSuchAlgorithmException ex) {
                            System.out.println("rebentou?");
                            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    if (line.contains("registar//") == true) {

                        String[] chavePubCliente = line.split("//");
                        System.out.println("Quero registar!");
                        //System.out.println("ChavepublicaCliente=> "+chavePubCliente[1]);
                        //receber chave publica

                        //String chavePublicaCliente=bufferedReader.readLine();
                        //System.out.println("chave publica cliente"+chavePublicaCliente);
                        byte[] publicKeyX = Base64.getDecoder().decode(chavePubCliente[1]);
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        //criar chave publica atraves dos bytes recebidos (DO CLIENTE)
                        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyX);
                        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
                        PublicKey a = kf.generatePublic(ks);
                        //System.out.println("a= "+a);

                        // guardar chave pública na pasta /pks/
                        keyUtils.SaveAlicePK(path + "/pks/" + StringUtil.getHexString(a.getEncoded()), a);

                        //gerar certificados e enviar
                        //gerar certificados e enviar
                        String pathd = Paths.get("").toAbsolutePath().toString();
                        CertOps cops = new CertOps();
                        keyUtils ku = new keyUtils();
                        StringUtil su = new StringUtil();

                        KeyPair kpServer = ku.LoadKeyPairServer(pathd, "ECDSA");
                        cops.createCertificate(false, kpServer.getPrivate(), a);
                        X509Certificate certClient = cops.generateCertificateChain(a);
                        //certClient.verify(kpServer.getPublic());
                        /* byte[] cadeia = Base64.getEncoder().encode(certClient.getEncoded());
                        String str = new String(cadeia);*/

                        //criar chave publica atraves dos bytes recebidos
                        printWriter.println("cadeia//.");
                        printWriter.flush();

                        //byte[] frame = certClient.getEncoded();
                        toServer.writeObject(certClient);

                        System.out.println(certClient);
                        /* System.out.println(cadeia);*/
                        System.out.println("TUDO OK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    } else if (line.contains("login//") == true) {
                        clients.add(sslSocket);
                        clientsRes.add(sslSocket);

                        // 1 - receber chave pública do cliente
                        String[] chavePubCliente = line.split("//");
                        System.out.println("Quero entrar!");
                        System.out.println("ChavepublicaCliente=> " + chavePubCliente[1]);

                        //receber chave publica
                        byte[] publicKeyX = Base64.getDecoder().decode(chavePubCliente[1]);
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        //criar chave publica atraves dos bytes recebidos (DO CLIENTE)
                        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyX);
                        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
                        PublicKey alice = kf.generatePublic(ks);
                        System.out.println("a= " + alice);
                        p = new Session(sslSocket, alice);
                        sess.add(p);
//                        boolean existePK = true;
//                        // 2 - verifica se a chave pública existe, se não existir recusa a ligação
//                        try {
//                            PublicKey aliceExiste = keyUtils.LoadAlicePublicKey(path + "/pks/" + StringUtil.getHexString(alice.getEncoded()), "ECDSA");
//                        } catch (Exception e) {
//                            existePK = false;
//                        }
//
//                        if (existePK) {
//                            // 3 - autenticação mutua
//
//                            // 4 - gera chaves de sessão para o cliente
//                            //chamar diffie helman para gerar chaves de sessao
//                            byte[] sessionKey = keyUtils.doECDH(keyUtils.LoadKeyPairServer(path, "ECDSA").getPrivate(), alice);
//                            System.out.println("Chave de Sessão: " + keyUtils.bytesToHex(sessionKey));
//
//                            byte[] sessionKeyA = new byte[sessionKey.length + 1];
//                            byte[] sessionKeyB = new byte[sessionKey.length + 1];
//                            byte[] sessionKeyC = new byte[sessionKey.length + 1];
//                            byte[] sessionKeyD = new byte[sessionKey.length + 1];
//                            sessionKeyA = Arrays.copyOf(sessionKey, sessionKey.length);
//                            sessionKeyA[sessionKeyA.length - 1] = 65;
//                            sessionKeyB = Arrays.copyOf(sessionKey, sessionKey.length);
//                            sessionKeyB[sessionKeyA.length - 1] = 66;
//                            sessionKeyC = Arrays.copyOf(sessionKey, sessionKey.length);
//                            sessionKeyC[sessionKeyA.length - 1] = 67;
//                            sessionKeyD = Arrays.copyOf(sessionKey, sessionKey.length);
//                            sessionKeyD[sessionKeyA.length - 1] = 68;
//
//                            MessageDigest digest;
//                            digest = MessageDigest.getInstance("SHA-256");
//                            byte[] hash = digest.digest(sessionKeyA);
//                            String chaveA = DatatypeConverter.printHexBinary(hash);
//
//                            hash = digest.digest(sessionKeyB);
//                            String chaveB = DatatypeConverter.printHexBinary(hash);
//
//                            hash = digest.digest(sessionKeyC);
//                            String chaveC = DatatypeConverter.printHexBinary(hash);
//
//                            hash = digest.digest(sessionKeyD);
//                            String chaveD = DatatypeConverter.printHexBinary(hash);
//                            Session s = new Session(chaveA, chaveB, chaveC, chaveD, sslSocket, alice);
//                            sess.add(s);
//
//                        }
                    } else if (line.contains("authDesafio//")) {
                        /*--------------------------------------*/

                        String[] auxKey = line.split("//");
                        byte[] publicKeyX = Base64.getDecoder().decode(auxKey[2]);
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

                        //criar chave publica atraves dos bytes recebidos (DO CLIENTE)
                        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyX);
                        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
                        PublicKey efemeralPK = kf.generatePublic(ks);

                        SecureRandom random = new SecureRandom();
                        int max = 500;
                        int min = 10;

                        int aux = random.nextInt(max - min + 1) + min;
                        RandomString desafiotoClient = new RandomString(aux);
                        String desafioEnviado = desafiotoClient.nextString();

                        printWriter.println("respostaDesafio//" + desafioEnviado);
                        printWriter.flush();

                        String[] leitura = line.split("//");
                        String desafio = leitura[1];
                        System.out.println("" + desafio);

                        KeyPair server = keyUtils.LoadKeyPairServer(path, "ECDSA");
                        byte[] sign = StringUtil.applyECDSASig(server.getPrivate(), desafio);
                        System.out.println("");
                        byte[] assinado = (byte[]) fromClient.readObject();
                        toServer.writeObject(sign);
                        System.out.println("" + Arrays.toString(sign));
                        Session r = new Session();
                        for (int i = 0; i < sess.size(); i++) {
                            if (sess.get(i).getSsl() == sslSocket) {
                                r = sess.get(i);
                            }
                        }
                        try {

                            boolean existePK = true;
                            // 2 - verifica se a chave pública existe, se não existir recusa a ligação
                            try {

                                PublicKey alice = r.getPk();
                                PublicKey aliceExiste = keyUtils.LoadAlicePublicKey(path + "/pks/" + StringUtil.getHexString(alice.getEncoded()), "ECDSA");
                            } catch (Exception e) {
                                existePK = false;
                            }

                            if (existePK) {
                                // 3 - autenticação mutua

                                // 4 - gera chaves de sessão para o cliente
                                //chamar diffie helman para gerar chaves de sessao
                                byte[] sessionKey = keyUtils.doECDH(keyUtils.LoadKeyPairServer(path, "ECDSA").getPrivate(), efemeralPK);
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
                                digest = MessageDigest.getInstance("SHA-1");
                                byte[] hash = digest.digest(sessionKeyA);
                                String chaveA = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyB);
                                String chaveB = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyC);
                                String chaveC = DatatypeConverter.printHexBinary(hash);

                                hash = digest.digest(sessionKeyD);
                                String chaveD = DatatypeConverter.printHexBinary(hash);
                                r.setChaveA(chaveA);
                                r.setChaveB(chaveB);
                                r.setChaveC(chaveC);
                                r.setChaveD(chaveD);
                                sess.add(r);

                            }
                            if (StringUtil.verifyECDSASig(r.getPk(), desafioEnviado, assinado)) {
                                System.out.println("Desafio correto, cliente autenticado.");
                            } else {
                                System.out.println("Desafio incorretoo, cliente não autenticado.");
                                sess.remove(r);
                                clients.remove(sslSocket);
                                clientsRes.remove(sslSocket);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            System.out.println("Desafio incorreto, cliente não autenticado.");
                            sess.remove(r);
                            clients.remove(sslSocket);
                            clientsRes.remove(sslSocket);
                        }

                    } else if (line.contains("LogOut//")) {
                        Session ro = new Session();
                        for (int i = 0; i < sess.size(); i++) {
                            if (sess.get(i).getSsl() == sslSocket) {
                                ro = sess.get(i);
                            }
                        }
                        sess.remove(ro);
                        clients.remove(sslSocket);
                        clientsRes.remove(sslSocket);
                    } else if (line.contains("transacao//") == true) {
                        System.out.println("-----Transação-----");
                        Transaction transacao = (Transaction) fromClient.readObject(); //ISTO DA ERRO

                        try {

                            if (StringUtil.verifyECDSASig(transacao.senderPublicKey, transacao.getDataSignature(), transacao.getSignatureSender()) == true) {
                                PublicKey EfetuaTransacao = transacao.senderPublicKey;

                                Float ValorTroca = transacao.getAmount();
                                KeyPair serv = keyUtils.LoadKeyPairServer(path, "ECDSA");

                                float amount = 0;
                                ArrayList<Transaction> transacoes = new ArrayList<Transaction>();
                                ObjectInputStream ob = new ObjectInputStream(new FileInputStream("transacoes.txt"));
                                transacoes = (ArrayList<Transaction>) ob.readObject();
                                ob.close();
                                for (Transaction i : transacoes) {
                                    String s = "" + i.getSenderPublicKey();
                                    String s1 = "" + EfetuaTransacao;
                                    String s3 = "" + i.getReceiverPublicKey();
                                    if (s.equals(s1)) {
                                        amount = amount - i.getAmount();
                                    }
                                    if (s3.equals(s1)) {
                                        amount = amount + i.getAmount();
                                    }
                                }
                                System.out.println(amount);
                                if (amount >= transacao.getAmount()) {
                                    transacao.generateSignatureServer(serv.getPrivate());
                                    transacoes.add(transacao);
                                    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("transacoes.txt"));
                                    oos.writeObject(transacoes);
                                    oos.close();
                                    System.out.println("Transação com sucesso!");
                                } else {
                                    System.out.println("Cliente sem dinheiro.");
                                }
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                    } else if (line.contains("Montante//") == true) {

                        ArrayList<Transaction> transacoes = new ArrayList<Transaction>();
                        ObjectInputStream ob = new ObjectInputStream(new FileInputStream("transacoes.txt"));
                        transacoes = (ArrayList<Transaction>) ob.readObject();
                        ob.close();
                        Session ro = new Session();
                        for (int i = 0; i < sess.size(); i++) {
                            if (sess.get(i).getSsl() == sslSocket) {
                                ro = sess.get(i);
                            }
                        }
                        float total = 0;
                        /* System.out.println(transacoes.size());
                        for (int i = 0; i < transacoes.size(); i++) {
                            System.out.println(transacoes.get(i));
                        }*/
                        String toReturn = "";
                        // ArrayList<Transaction> tran = new ArrayList<Transaction>();
                        for (int i = 0; i < transacoes.size(); i++) {
                            String s = "" + transacoes.get(i).getReceiverPublicKey();
                            String s1 = "" + ro.getPk();
                            if (s.equals(s1)) {
                                //tran.add(transacoes.get(i));
                                toReturn = toReturn + transacoes.get(i).getSenderPublicKey() + "Sender: " + transacoes.get(i).getSenderPublicKey() + "\nReceiver: " + transacoes.get(i).getReceiverPublicKey() + "\nAmount: +" + transacoes.get(i).getAmount() + "\n\n";
                                total = total + transacoes.get(i).getAmount();
                            }
                            String s2 = "" + transacoes.get(i).getSenderPublicKey();
                            if (s2.equals(s1)) {
                                //tran.add(transacoes.get(i));
                                toReturn = toReturn + transacoes.get(i).getSenderPublicKey() + "Sender: " + transacoes.get(i).getSenderPublicKey() + "\nReceiver: " + transacoes.get(i).getReceiverPublicKey() + "\nAmount: -" + transacoes.get(i).getAmount() + "\n\n";
                                total = total - transacoes.get(i).getAmount();
                            }
                        }

                        String returnValue2 = toReturn.replaceAll("(\\r|\\n)", ".|");

                        
                        
                        
                        String envia = total + "/////" + returnValue2;
                        
                        
                        
                        AESEncryption es = new AESEncryption();
                        envia = es.encyrpt(envia, ro.getChaveB());
                        String toCalcMac = "Montante/////" + envia + "/////" + es.getSalta() + "/////" + es.getIv();
                        String MAC = Base64.getEncoder().encodeToString(StringUtil.generateHMac(toCalcMac, ro.getChaveD()));
                        printWriter.println("Montante/////" + envia + "/////" + es.getSalta() + "/////" + es.getIv() + "//" + MAC);
                        printWriter.flush();

                        
                        
                        
                        
                        
                      /*  printWriter.println("Montante//" + total + "//" + returnValue2);
                        printWriter.flush();*/
                        System.out.println("ola");
                        //toServer.writeObject(tran);
                        System.out.println("xau");
                    }

                    if (line.trim().equals("007")) {
                        break;
                    }
                }
                // Write data
                sslSocket.close();
            } catch (Exception ex) {
                Session r = new Session();
                for (int i = 0; i < sess.size(); i++) {
                    if (sess.get(i).getSsl() == sslSocket) {
                        r = sess.get(i);
                    }
                }
                sess.remove(r);
                clients.remove(sslSocket);
                clientsRes.remove(sslSocket);
                System.out.println("foi neste que rebentou 3");
                if (clients.size() == 0) {
                    flag2 = 0;
                }
                //APAGAR ESTE
                ex.printStackTrace();
            }
        }
    }

//    static class ServerThreadEnvia implements Runnable {
//
//        private SSLSocket sslSocket = null;
//
//        ServerThreadEnvia(SSLSocket sslSocket) {
//            this.sslSocket = sslSocket;
//        }
//
//        public void run() {
//            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
//
//            try {
//                // Start handshake
//                sslSocket.startHandshake();
//
//                // Get session after the connection is established
//                SSLSession sslSession = sslSocket.getSession();
//
//                // Start handling application content
//                InputStream inputStream = sslSocket.getInputStream();
//                OutputStream outputStream = sslSocket.getOutputStream();
//
//                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
//                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
//
//                while (true) {
////exemoplio
//                    //z if (estado == false) {
//                    //  printWriter.println("./.");
//                    // printWriter.flush();
//                    // }
//                    /* printWriter.println("ola eu sou o server envia particular");
//                    printWriter.flush();
//                    sleep(60000);*/
//                }
//
//            } catch (Exception ex) {
//                System.out.println("foi neste que rebentou 4");
//                ex.printStackTrace();
//            }
//        }
//    }
    static class ServerThreadEnviaAll implements Runnable {

        public ServerThreadEnviaAll() {
        }

        public void run() {
            String k = "";
            for (int i = 0; i < clients.size(); i++) {
                clientsRes.set(i, clients.get(i));
            }
            while (true) {

                if (clientsRes.size() == clients.size()) {
                    System.out.println("envia desafio");
                    // if (estado == false) {
                    k = rand.randomnumber();

                    MessageDigest digest;
                    try {
                        digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(k.getBytes(StandardCharsets.UTF_8));
                        String hex = DatatypeConverter.printHexBinary(hash);
                        desafioslista.add(hex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    // }
                    int flag = 0;

                    if (time > 40000) {
                        bits--;
                    }
                    if (time < 25000) {
                        bits++;
                    }

                    for (int i = 0; i < clients.size(); i++) {
                        clients.get(i).setEnabledCipherSuites(clients.get(i).getSupportedCipherSuites());
                        try {
                            // Start handshake

                            clients.get(i).startHandshake();
                            OutputStream outputStream = clients.get(i).getOutputStream();
                            PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                            InputStream inputStream = clients.get(i).getInputStream();

                            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                            // Get session after the connection is established
                            // SSLSession sslSession = clients.get(i).getSession();

                            if (estado == true && !clients.get(i).getInetAddress().getHostAddress().equals(quemresolveu)) {

                                flag = 1;

                            }

                            if (flag2 == 0) {

                                String envia = k + "//" + bits;
                                AESEncryption es = new AESEncryption();
                                Session ra = new Session();
                                for (int j = 0; j < sess.size(); j++) {
                                    if (sess.get(j).getSsl() == clients.get(i)) {
                                        ra = sess.get(j);
                                    }
                                }
                                envia = es.encyrpt(envia, ra.getChaveB());
                                
                                String toCalcMac = "desafio//" + envia + "//" + es.getSalta() + "//" + es.getIv();
                                String MAC = Base64.getEncoder().encodeToString(StringUtil.generateHMac(toCalcMac, ra.getChaveD()));
                                
                                printWriter.println("desafio//" + envia + "//" + es.getSalta() + "//" + es.getIv() + "//" + MAC);
                                printWriter.flush();

                                System.out.println("os meus bits estao em : " + bits);
                                /* printWriter.println("desafio//" + k + "//" + bits);*****
                                printWriter.flush();*/
                                startTime = System.currentTimeMillis();
                                if (clients.size() - 1 == i) {
                                    flag2 = 1;
                                }

                            }
                            if (flag == 1 && clients.size() - 1 == i) {
                                estado = false;
                                quemresolveu = null;
                                flag = 0;

                            }

                            // Write data
                            // clients.get(i).close();
                        } catch (Exception ex) {
                            System.out.println("foi neste que rebentou 66");
                            ex.printStackTrace();
                        }
                    }

                    try {
                        clientsRes = new ArrayList<SSLSocket>();
                        sleep(30000);

                    } catch (InterruptedException ex) {
                        Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
            }
            //stop();
        }
    }

}
