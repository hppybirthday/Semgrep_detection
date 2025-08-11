import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class FileEncryptor {
    private static final String KEY = "ThisIsASecretKey";
    private static final String BASE_DIR = "/var/secure_files/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== File Encryptor/Decryptor ===");
        System.out.println("Enter operation (encrypt/decrypt): ");
        String operation = scanner.nextLine();
        
        System.out.println("Enter filename: ");
        String filename = scanner.nextLine();
        
        try {
            if ("encrypt".equalsIgnoreCase(operation)) {
                encryptFile(filename);
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                decryptFile(filename);
            } else {
                System.out.println("Invalid operation");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filename) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        // VULNERABLE PATH CONSTRUCTION
        File inputFile = new File(BASE_DIR + filename);
        FileInputStream fis = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        fis.read(inputBytes);
        
        byte[] encrypted = cipher.doFinal(inputBytes);
        File outputFile = new File(BASE_DIR + filename + ".enc");
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(encrypted);
        
        System.out.println("Encrypted to: " + outputFile.getAbsolutePath());
        fis.close();
        fos.close();
    }

    private static void decryptFile(String filename) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        
        File inputFile = new File(BASE_DIR + filename);
        FileInputStream fis = new FileInputStream(inputFile);
        byte[] encryptedBytes = new byte[(int) inputFile.length()];
        fis.read(encryptedBytes);
        
        byte[] decrypted = cipher.doFinal(encryptedBytes);
        String outputFilename = filename.replace(".enc", "");
        File outputFile = new File(BASE_DIR + outputFilename + ".decrypted");
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(decrypted);
        
        System.out.println("Decrypted to: " + outputFile.getAbsolutePath());
        fis.close();
        fos.close();
    }
}