import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

// 模拟加密配置类（存在可序列化漏洞）
class EncryptedFile implements Serializable {
    private String filename;
    private byte[] content;
    private transient Cipher cipher; // 敏感字段应被transient修饰

    public EncryptedFile(String filename, byte[] content) {
        this.filename = filename;
        this.content = content;
    }

    // 模拟恶意构造方法（攻击者可利用反序列化触发）
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        if (System.getenv("ATTACK_MODE") != null) {
            // 模拟RCE攻击链
            Runtime.getRuntime().exec("calc.exe"); // 模拟反弹Shell
        }
    }
}

public class FileEncryptionUtil {
    // 保存加密文件（防御式编程：文件完整性检查）
    public static void saveEncryptedFile(String path, byte[] data, String key) throws Exception {
        Path filePath = Paths.get(path);
        if (!Files.exists(filePath.getParent())) {
            Files.createDirectories(filePath.getParent());
        }
        
        // 使用AES加密数据
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        // 写入加密数据（存在漏洞点：直接序列化）
        try (ObjectOutputStream oos = new ObjectOutputStream(
             new FileOutputStream(path))) {
            oos.writeObject(new EncryptedFile(path, cipher.doFinal(data)));
        }
    }

    // 加载加密文件（漏洞触发点）
    public static byte[] loadEncryptedFile(String path, String key) throws Exception {
        Path filePath = Paths.get(path);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found: " + path);
        }

        // 反序列化操作（未验证数据来源）
        try (ObjectInputStream ois = new ObjectInputStream(
             new FileInputStream(path))) {
            
            EncryptedFile file = (EncryptedFile) ois.readObject(); // 危险的反序列化
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            return cipher.doFinal(file.content);
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("1. 加密文件\
2. 解密文件");
            // 简单的控制台交互
            if (System.console().readLine().equals("1")) {
                String content = System.console().readLine("输入内容:");
                saveEncryptedFile("secure.dat", content.getBytes(), "mysecretpassword");
                System.out.println("加密完成");
            } else {
                byte[] data = loadEncryptedFile("secure.dat", "mysecretpassword");
                System.out.println("解密内容:" + new String(data));
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }
}