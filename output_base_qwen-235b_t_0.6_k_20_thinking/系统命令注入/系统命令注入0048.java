import java.io.*;
import java.util.Scanner;

public class FileCrypt {
    public static void main(String[] args) throws IOException {
        Scanner sc = new Scanner(System.in);
        System.out.println("1. Encrypt\
2. Decrypt");
        int choice = Integer.parseInt(sc.nextLine());
        System.out.print("File path: ");
        String file = sc.nextLine();
        System.out.print("Password: ");
        String pass = sc.nextLine();
        
        try {
            String cmd = "";
            if(choice == 1) {
                cmd = "openssl enc -aes-256-cbc -in " + file + " -out " + file + ".enc -pass pass:" + pass;
            } else if(choice == 2) {
                cmd = "openssl enc -d -aes-256-cbc -in " + file + " -out " + file.replace(".enc", "") + " -pass pass:" + pass;
            }
            
            Process proc = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream()));
            BufferedReader error = new BufferedReader(
                new InputStreamReader(proc.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            while ((line = error.readLine()) != null) {
                System.err.println(line);
            }
            
        } catch (Exception e) {
            System.err.println("Operation failed");
        }
    }
}