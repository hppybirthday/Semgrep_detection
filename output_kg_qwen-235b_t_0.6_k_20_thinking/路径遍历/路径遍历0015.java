import java.io.*;
import java.util.Scanner;

public class FileCryptoTool {
    private static final String BASE_DIR = "/safe_storage/";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("输入操作类型(encrypt/decrypt): ");
        String operation = scanner.nextLine();
        
        System.out.print("输入文件名: ");
        String filename = scanner.nextLine();
        
        try {
            if ("encrypt".equalsIgnoreCase(operation)) {
                encryptFile(filename);
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                decryptFile(filename);
            } else {
                System.out.println("无效操作类型");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }

    private static void encryptFile(String filename) throws IOException {
        File inputFile = new File(BASE_DIR + filename);
        File encryptedFile = new File(BASE_DIR + filename + ".enc");
        
        if (!inputFile.exists()) {
            throw new FileNotFoundException("文件未找到: " + filename);
        }
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                // 简单加密：字节异或0xFF
                for (int i = 0; i < bytesRead; i++) {
                    buffer[i] = (byte) ~buffer[i];
                }
                fos.write(buffer, 0, bytesRead);
            }
        }
        
        System.out.println("加密完成: " + encryptedFile.getAbsolutePath());
    }

    private static void decryptFile(String filename) throws IOException {
        File encryptedFile = new File(BASE_DIR + filename);
        File decryptedFile = new File(BASE_DIR + filename.replace(".enc", ""));
        
        if (!encryptedFile.exists()) {
            throw new FileNotFoundException("加密文件未找到: " + filename);
        }
        
        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(decryptedFile)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                // 解密：再次异或0xFF
                for (int i = 0; i < bytesRead; i++) {
                    buffer[i] = (byte) ~buffer[i];
                }
                fos.write(buffer, 0, bytesRead);
            }
        }
        
        System.out.println("解密完成: " + decryptedFile.getAbsolutePath());
    }
}