package sss;

import java.io.*;

public class Ler {

    public static String umaString() {
        String s = "";
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            s = in.readLine();
        } catch (IOException e) {
            System.out.println("Erro ao ler fluxo de entrada.");
        }
        return s;
    }

    public static int umInt() {
        while (true) {
            try {
                return Integer.valueOf(umaString().trim()).intValue();
            } catch (Exception e) {
                System.out.println("Não é um inteiro válido!!!");
            }
        }
    }

    public static Double umDouble() {
        while (true) {
            try {
                return Double.valueOf(umaString().trim()).doubleValue();
            } catch (Exception e) {
                System.out.println("Não é um double válido!!!");
            }
        }
    }

    public static Float umFloat() {
        while (true) {
            try {
                return Float.valueOf(umaString().trim()).floatValue();
            } catch (Exception e) {
                System.out.println("Não é um float válido!!!");
            }
        }
    }

    public static boolean umBoolean() {
        while (true) {
            try {
                return Boolean.valueOf(umaString().trim()).booleanValue(); //o trim tira os espaços em branco e o return
            } catch (Exception e) {
                System.out.println("Não é um boolean válido!!!");
            }
        }
    }

    public static char umChar() {
        while (true) {
            try {
                return umaString().trim().charAt(0);
            } catch (Exception e) {
                System.out.println("Não é um char válido!!!");
            }
        }
    }

    public static long umLong() {
        while (true) {
            try {
                return Long.valueOf(umaString().trim()).longValue();
            } catch (Exception e) {
                System.out.println("Não é um long válido!!!");
            }
        }
    }

}
