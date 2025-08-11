import java.io.*;
import java.util.Scanner;

public class FileCrypt {
    static final String BASE_DIR = "./storage/";
    
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("1.Encrypt 2.Decrypt");
        int op = Integer.parseInt(sc.nextLine());
        
        System.out.print("Input file: ");
        String inFile = sc.nextLine();
        System.out.print("Output file: ");
        String outFile = sc.nextLine();
        
        try {
            if(op == 1) {
                encrypt(inFile, outFile);
            } else if(op == 2) {
                decrypt(inFile, outFile);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
    
    static void encrypt(String in, String out) throws Exception {
        File src = new File(BASE_DIR + in);
        File dst = new File(BASE_DIR + out);
        FileInputStream fis = new FileInputStream(src);
        FileOutputStream fos = new FileOutputStream(dst);
        int b;
        while((b = fis.read()) != -1) {
            fos.write(b ^ 0xFF);
        }
        fis.close();
        fos.close();
    }
    
    static void decrypt(String in, String out) throws Exception {
        File src = new File(BASE_DIR + in);
        File dst = new File(BASE_DIR + out);
        FileInputStream fis = new FileInputStream(src);
        FileOutputStream fos = new FileOutputStream(dst);
        int b;
        while((b = fis.read()) != -1) {
            fos.write(b ^ 0xFF);
        }
        fis.close();
        fos.close();
    }
}