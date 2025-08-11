import java.io.*;
import java.util.Scanner;

public class FileEncryptorDecryptor {
    private static final String BASE_DIR = "secure_storage/";
    private static final String ENCRYPTION_KEY = "secret123";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作(1/2): ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除换行符
        
        System.out.print("请输入文件路径: ");
        String userInput = scanner.nextLine();
        
        String targetPath = BASE_DIR + userInput;
        
        try {
            if (choice == 1) {
                encryptFile(targetPath);
            } else if (choice == 2) {
                decryptFile(targetPath);
            } else {
                System.out.println("无效的选择!");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }

    private static void encryptFile(String filePath) throws IOException {
        File inputFile = new File(filePath);
        File encryptedFile = new File(filePath + ".enc");
        
        try (InputStream is = new FileInputStream(inputFile);
             OutputStream os = new FileOutputStream(encryptedFile)) {
            
            int data;
            int keyIndex = 0;
            while ((data = is.read()) > -1) {
                int encryptedByte = data ^ ENCRYPTION_KEY.charAt(keyIndex % ENCRYPTION_KEY.length());
                os.write(encryptedByte);
                keyIndex++;
            }
        }
        
        System.out.println("文件加密成功: " + encryptedFile.getAbsolutePath());
        inputFile.delete();
    }

    private static void decryptFile(String filePath) throws IOException {
        if (!filePath.endsWith(".enc")) {
            throw new IllegalArgumentException("只能解密.enc文件");
        }
        
        File encryptedFile = new File(filePath);
        File decryptedFile = new File(filePath.substring(0, filePath.length() - 4));
        
        try (InputStream is = new FileInputStream(encryptedFile);
             OutputStream os = new FileOutputStream(decryptedFile)) {
            
            int data;
            int keyIndex = 0;
            while ((data = is.read()) > -1) {
                int decryptedByte = data ^ ENCRYPTION_KEY.charAt(keyIndex % ENCRYPTION_KEY.length());
                os.write(decryptedByte);
                keyIndex++;
            }
        }
        
        System.out.println("文件解密成功: " + decryptedFile.getAbsolutePath());
        encryptedFile.delete();
    }
}