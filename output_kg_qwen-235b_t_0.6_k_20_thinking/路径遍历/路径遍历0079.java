import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;
import java.util.Scanner;

public class FileEncryptor {
    private static final String BASE_DIR = "/opt/app/secure_files/";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final byte[] ENCRYPTION_KEY = "1234567890123456".getBytes();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作(1/2): ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除换行符
        
        System.out.print("请输入文件名: ");
        String filename = scanner.nextLine();
        
        try {
            if (choice == 1) {
                encryptFile(filename);
            } else if (choice == 2) {
                decryptFile(filename);
            } else {
                System.out.println("无效的选择");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filename) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        // 漏洞点：直接拼接用户输入构造路径
        Path inputPath = Paths.get(BASE_DIR + filename);
        Path outputPath = Paths.get(BASE_DIR + filename + ".enc");
        
        if (!Files.exists(inputPath)) {
            throw new FileNotFoundException("文件不存在: " + filename);
        }
        
        try (InputStream in = Files.newInputStream(inputPath);
             OutputStream out = Files.newOutputStream(outputPath);
             CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
            
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                cos.write(buffer, 0, read);
            }
        }
        
        System.out.println("加密成功，文件保存为: " + outputPath.toString());
    }

    private static void decryptFile(String filename) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        
        // 漏洞点：直接拼接用户输入构造路径
        Path inputPath = Paths.get(BASE_DIR + filename);
        Path outputPath = Paths.get(BASE_DIR + filename.replace(".enc", "_decrypted"));
        
        if (!Files.exists(inputPath)) {
            throw new FileNotFoundException("文件不存在: " + filename);
        }
        
        try (InputStream in = new CipherInputStream(Files.newInputStream(inputPath), cipher);
             OutputStream out = Files.newOutputStream(outputPath)) {
            
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
        
        System.out.println("解密成功，文件保存为: " + outputPath.toString());
    }
}