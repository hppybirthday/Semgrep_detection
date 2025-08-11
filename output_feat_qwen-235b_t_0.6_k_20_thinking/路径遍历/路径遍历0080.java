import java.io.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class FileEncryptorDecryptor {
    private static final String BASE_DIR = "/var/secure_storage/";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java FileEncryptorDecryptor <encrypt|decrypt> <inputFile> <outputDir> <password>");
            return;
        }

        String operation = args[0];
        String inputFile = args[1];
        String outputDir = args[2];
        String password = args[3];

        try {
            // Vulnerable path construction
            Path outputPath = Paths.get(BASE_DIR, outputDir);
            
            if (operation.equalsIgnoreCase("encrypt")) {
                encryptFile(inputFile, outputPath.toString(), password);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                decryptFile(inputFile, outputPath.toString(), password);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
            
            // Vulnerable delete function
            if (operation.equalsIgnoreCase("delete")) {
                deleteFile(outputPath.toString());
            }
            
        } catch (Exception e) {
            System.err.println("Error during operation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String inputFile, String outputDir, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));
        
        byte[] fileContent = Files.readAllBytes(Paths.get(BASE_DIR, inputFile));
        byte[] encryptedContent = cipher.doFinal(fileContent);
        
        Files.write(Paths.get(outputDir, "encrypted_" + inputFile), encryptedContent);
        System.out.println("File encrypted successfully");
    }

    private static void decryptFile(String inputFile, String outputDir, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(password));
        
        byte[] encryptedContent = Files.readAllBytes(Paths.get(outputDir, inputFile));
        byte[] decryptedContent = cipher.doFinal(encryptedContent);
        
        Files.write(Paths.get(outputDir, "decrypted_" + inputFile), decryptedContent);
        System.out.println("File decrypted successfully");
    }

    private static void deleteFile(String filePath) throws IOException {
        // Vulnerable delete operation
        Files.delete(Paths.get(filePath));
        System.out.println("File deleted: " + filePath);
    }

    private static javax.crypto.SecretKey getSecretKey(String password) {
        return new SecretKeySpec(password.getBytes(), ALGORITHM);
    }
}