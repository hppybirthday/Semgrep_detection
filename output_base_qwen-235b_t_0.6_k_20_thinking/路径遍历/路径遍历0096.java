import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    private static final String ENCRYPTION_KEY = "secret123";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作: ");
        
        int choice = Integer.parseInt(scanner.nextLine());
        
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        
        try {
            if (choice == 1) {
                encryptFile(filePath);
            } else if (choice == 2) {
                decryptFile(filePath);
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }
    
    private static void encryptFile(String filePath) throws IOException {
        File inputFile = new File(filePath);
        File encryptedFile = new File(filePath + ".encrypted");
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            
            int data;
            int keyIndex = 0;
            while ((data = fis.read()) != -1) {
                fos.write(data ^ ENCRYPTION_KEY.charAt(keyIndex % ENCRYPTION_KEY.length()));
                keyIndex++;
            }
        }
        System.out.println("加密完成: " + encryptedFile.getAbsolutePath());
    }
    
    private static void decryptFile(String filePath) throws IOException {
        File encryptedFile = new File(filePath);
        File outputFile = new File(filePath.replace(".encrypted", ""));
        
        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            int data;
            int keyIndex = 0;
            while ((data = fis.read()) != -1) {
                fos.write(data ^ ENCRYPTION_KEY.charAt(keyIndex % ENCRYPTION_KEY.length()));
                keyIndex++;
            }
        }
        System.out.println("解密完成: " + outputFile.getAbsolutePath());
    }
}