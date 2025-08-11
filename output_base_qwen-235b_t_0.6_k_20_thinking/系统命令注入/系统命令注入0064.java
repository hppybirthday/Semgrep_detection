import java.io.*;
import java.util.Scanner;

public class FileEncryptionTool {
    // 模拟加密工具配置
    private static final String ENCRYPTION_TOOL = "openssl";
    private static final String TEMP_KEY_FILE = ".temp_key_";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入操作类型(encrypt/decrypt): ");
        String operation = scanner.nextLine();
        
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        
        System.out.print("请输入密码(注意：不要包含特殊字符): ");
        String password = scanner.nextLine();
        
        try {
            if ("encrypt".equalsIgnoreCase(operation)) {
                encryptFile(filePath, password);
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                decryptFile(filePath, password);
            } else {
                System.out.println("无效的操作类型");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }
    
    private static void encryptFile(String filePath, String password) throws IOException {
        String encryptedFile = filePath + ".enc";
        String command = ENCRYPTION_TOOL + " enc -aes-256-cbc -in " + filePath + 
                       " -out " + encryptedFile + " -k " + password;
        
        // 模拟防御措施（错误实现）
        if (password.contains(";") || password.contains("&")) {
            throw new IllegalArgumentException("密码包含非法字符");
        }
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("加密成功，文件保存为: " + encryptedFile);
            }
        } catch (Exception e) {
            throw new IOException("加密失败: " + e.getMessage());
        }
    }
    
    private static void decryptFile(String filePath, String password) {
        // 解密逻辑省略，实际可能使用类似实现
    }
}