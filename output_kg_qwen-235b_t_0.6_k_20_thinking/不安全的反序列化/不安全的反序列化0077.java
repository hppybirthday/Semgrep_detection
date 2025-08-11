import java.io.*;
import java.nio.file.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

// 加密数据封装类
class EncryptedData implements Serializable {
    private static final long serialVersionUID = 1L;
    public String encryptedContent;
    public String encryptionKey;
    
    public EncryptedData(String content, String key) {
        this.encryptedContent = content;
        this.encryptionKey = key;
    }
}

// 文件加解密工具类
class FileEncryptor {
    
    // 加密文件
    public static void encryptFile(String inputPath, String outputPath, String secretKey) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(inputPath));
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(fileData);
        
        // 创建包含加密数据的对象
        EncryptedData data = new EncryptedData(Base64.getEncoder().encodeToString(encrypted), secretKey);
        
        // 序列化加密数据到文件
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outputPath))) {
            oos.writeObject(data);
        }
    }
    
    // 解密文件（存在不安全反序列化漏洞）
    public static String decryptFile(String filePath) throws Exception {
        // 漏洞点：直接反序列化不可信数据
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            EncryptedData data = (EncryptedData) ois.readObject();
            
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(data.encryptionKey.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data.encryptedContent));
            return new String(decrypted);
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟攻击代码
        Runtime.getRuntime().exec("calc");
    }
}

public class FileEncryptionTool {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java FileEncryptionTool [encrypt|decrypt] [file] [output] [key]");
            return;
        }
        
        try {
            String command = args[0];
            if (command.equals("encrypt")) {
                if (args.length < 5) {
                    System.out.println("Missing parameters for encryption");
                    return;
                }
                encryptFile(args[1], args[2], args[3]);
                System.out.println("File encrypted successfully");
            } 
            else if (command.equals("decrypt")) {
                if (args.length < 2) {
                    System.out.println("Missing parameters for decryption");
                    return;
                }
                String content = decryptFile(args[1]);
                System.out.println("Decrypted content: " + content);
            }
            else {
                System.out.println("Invalid command");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Operation failed: " + e.getMessage());
        }
    }
}