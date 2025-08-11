import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class FileEncryptorDecryptor {
    private static final String BASE_DIR = "./data/";
    
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java FileEncryptorDecryptor <encrypt|decrypt> <prefix> <suffix>");
            return;
        }

        String operation = args[0];
        String prefix = args[1];
        String suffix = args[2];
        
        try {
            if (operation.equalsIgnoreCase("encrypt")) {
                encryptFile(prefix, suffix);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                decryptFile(prefix, suffix);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error during file operation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String prefix, String suffix) throws IOException {
        String inputFilePath = BASE_DIR + prefix + "original_" + suffix;
        String outputFilePath = BASE_DIR + prefix + "encrypted_" + suffix;
        
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFilePath));
        // Simple XOR encryption for demonstration
        for (int i = 0; i < fileContent.length; i++) {
            fileContent[i] = (byte) (fileContent[i] ^ 0xA5);
        }
        
        Files.write(Paths.get(outputFilePath), fileContent);
        System.out.println("File encrypted successfully to: " + outputFilePath);
    }

    private static void decryptFile(String prefix, String suffix) throws IOException {
        String inputFilePath = BASE_DIR + prefix + "encrypted_" + suffix;
        String outputFilePath = BASE_DIR + prefix + "decrypted_" + suffix;
        
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFilePath));
        // Simple XOR decryption (same as encryption)
        for (int i = 0; i < fileContent.length; i++) {
            fileContent[i] = (byte) (fileContent[i] ^ 0xA5);
        }
        
        Files.write(Paths.get(outputFilePath), fileContent);
        System.out.println("File decrypted successfully to: " + outputFilePath);
    }
}