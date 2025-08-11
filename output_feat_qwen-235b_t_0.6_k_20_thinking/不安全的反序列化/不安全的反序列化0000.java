import java.io.File;
import java.io.IOException;
import java.util.Scanner;
import com.fasterxml.jackson.databind.ObjectMapper;

public class FileEncryptorDecryptor {
    static class SystemConfig {
        String encryptionKey;
        boolean debugMode;
        
        // 模拟存在漏洞的配置更新方法
        public static void updateConfigs(String filePath) throws IOException {
            ObjectMapper mapper = new ObjectMapper();
            // "不安全的反序列化"漏洞点：直接反序列化不可信数据
            Object config = mapper.readValue(new File(filePath), Object.class);
            System.out.println("[+] 配置更新成功: " + config.getClass().getName());
        }
    }

    // 模拟加密功能（实际加密逻辑不重要）
    static void encryptFile(String path, String key) {
        System.out.println("[INFO] 使用密钥 " + key + " 加密文件 " + path);
        // 实际加密逻辑...
    }

    // 模拟解密功能
    static void decryptFile(String path, String key) {
        System.out.println("[INFO] 使用密钥 " + key + " 解密文件 " + path);
        // 实际解密逻辑...
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            System.out.println("=== 文件加密解密工具 ===");
            System.out.print("请输入操作类型(encrypt/decrypt): ");
            String operation = scanner.nextLine();
            
            System.out.print("请输入文件路径: ");
            String filePath = scanner.nextLine();
            
            System.out.print("请输入密钥: ");
            String key = scanner.nextLine();
            
            // 模拟加载外部配置（存在漏洞）
            System.out.println("[*] 正在更新系统配置...");
            SystemConfig.updateConfigs(filePath + ".config");  // 假设配置文件与数据文件关联
            
            // 执行加密/解密操作
            if (operation.equalsIgnoreCase("encrypt")) {
                encryptFile(filePath, key);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                decryptFile(filePath, key);
            } else {
                System.out.println("[ERROR] 无效的操作类型");
            }
            
        } catch (Exception e) {
            System.out.println("[ERROR] 操作失败: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}