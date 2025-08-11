import java.io.*;
import java.util.Scanner;

class FileEncryptorDecryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("1. Encrypt\
2. Decrypt");
        int choice = scanner.nextInt();
        scanner.nextLine();
        System.out.print("Enter filename: ");
        String file = scanner.nextLine();
        System.out.print("Enter password: ");
        String pass = scanner.nextLine();
        try {
            if(choice == 1) {
                String[] cmd = {"sh", "-c", "openssl enc -aes-256-cbc -in " + file + " -out " + file + ".enc -pass pass:" + pass};
                new ProcessBuilder(cmd).start();
            } else if(choice == 2) {
                String[] cmd = {"sh", "-c", "openssl enc -d -aes-256-cbc -in " + file + " -out " + file.replace(".enc", "") + " -pass pass:" + pass};
                new ProcessBuilder(cmd).start();
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}