import java.io.*;
import java.util.Scanner;

// 配置类（可序列化）
class EncryptionConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    String algorithm;
    String key;
    
    public EncryptionConfig(String algorithm, String key) {
        this.algorithm = algorithm;
        this.key = key;
    }
}

// 加密工具类
class EncryptionUtil {
    public static void saveConfig(EncryptionConfig config, String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(config);
            System.out.println("[+] 配置已保存到 " + filename);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 解密工具类
class DecryptionUtil {
    public static EncryptionConfig readConfig(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 漏洞点：直接反序列化不可信数据
            return (EncryptionConfig) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 模拟攻击者恶意类
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("calc"); // 模拟任意代码执行
    }
}

// 主程序
class FileCryptTool {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 生成配置文件");
        System.out.println("2. 解密文件（漏洞点）");
        System.out.print("请选择操作: ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除缓冲区
        
        if (choice == 1) {
            System.out.print("输入加密算法: ");
            String algo = scanner.nextLine();
            System.out.print("输入密钥: ");
            String key = scanner.nextLine();
            EncryptionUtil.saveConfig(new EncryptionConfig(algo, key), "config.dat");
        } else if (choice == 2) {
            System.out.println("[!] 正在加载配置文件（存在漏洞）...");
            EncryptionConfig config = DecryptionUtil.readConfig("config.dat");
            if (config != null) {
                System.out.println("[+] 使用算法: " + config.algorithm);
                System.out.println("[+] 密钥: " + config.key);
                // 实际解密逻辑（模拟）
                System.out.println("[+] 文件解密完成");
            }
        }
        scanner.close();
    }
}