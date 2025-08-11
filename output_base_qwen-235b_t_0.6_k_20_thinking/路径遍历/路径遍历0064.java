import java.io.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class FileCryptor {
    private static final String ALGORITHM = "AES";
    private static final byte[] keyValue = 
        new byte[]{'T', 'h', 'i', 's', 'I', 's', 'A', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileCryptor <encrypt|decrypt> <inputPath> <outputPath>");
            return;
        }

        String mode = args[0];
        String inputPath = args[1];
        String outputPath = args[2];

        try {
            if (mode.equalsIgnoreCase("encrypt")) {
                encryptFile(inputPath, outputPath);
            } else if (mode.equalsIgnoreCase("decrypt")) {
                decryptFile(inputPath, outputPath);
            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error during operation: " + e.getMessage());
            // 漏洞点：记录详细路径信息可能暴露系统结构
            System.err.println("Input path: " + inputPath);
        }
    }

    private static void encryptFile(String inputPath, String outputPath) throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, inputPath, outputPath);
    }

    private static void decryptFile(String inputPath, String outputPath) throws Exception {
        doCrypto(Cipher.DECRYPT_MODE, inputPath, outputPath);
    }

    private static void doCrypto(int cipherMode, String inputPath, String outputPath) throws Exception {
        // 漏洞点：直接使用用户输入的路径构造文件对象
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputPath);
        }

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(keyValue, ALGORITHM);
        cipher.init(cipherMode, keySpec);

        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    out.write(output);
                }
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                out.write(outputBytes);
            }
        }
    }
}