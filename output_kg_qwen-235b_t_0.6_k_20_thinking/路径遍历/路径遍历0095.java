import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class FileEncryptor {
    private static final String BASE_DIR = "/var/secure_files/";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptor <encrypt|decrypt> <inputFilename> <outputFilename>");
            return;
        }

        String operation = args[0];
        String inputFilename = args[1];
        String outputFilename = args[2];

        try {
            if (operation.equalsIgnoreCase("encrypt")) {
                encrypt(inputFilename, outputFilename);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                decrypt(inputFilename, outputFilename);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void encrypt(String inputFilename, String outputFilename) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // VULNERABLE PATH CONSTRUCTION
        File inputFile = new File(BASE_DIR + inputFilename);
        File outputFile = new File(BASE_DIR + outputFilename);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            
            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);
        }
    }

    public static void decrypt(String inputFilename, String outputFilename) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        // VULNERABLE PATH CONSTRUCTION
        File inputFile = new File(BASE_DIR + inputFilename);
        File outputFile = new File(BASE_DIR + outputFilename);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            
            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);
        }
    }
}