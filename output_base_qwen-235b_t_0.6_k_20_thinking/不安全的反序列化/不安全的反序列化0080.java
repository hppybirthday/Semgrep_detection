import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

class EncryptionConfig implements Serializable {
    private String algorithm;
    private String key;

    public EncryptionConfig(String algorithm, String key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    public String getAlgorithm() { return algorithm; }
    public String getKey() { return key; }
}

public class FileEncryptor {
    // 模拟保存加密配置（包含敏感信息）
    public static void saveConfig(String filename) throws Exception {
        EncryptionConfig config = new EncryptionConfig("AES", "secretKey123");
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(config);
        }
    }

    // 模拟加载配置（存在不安全反序列化）
    public static EncryptionConfig loadConfig(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 危险：直接反序列化不可信数据
            return (EncryptionConfig) ois.readObject();
        }
    }

    // 模拟解密过程
    public static String decrypt(String encryptedData, EncryptionConfig config) throws Exception {
        Cipher cipher = Cipher.getInstance(config.getAlgorithm());
        SecretKeySpec keySpec = new SecretKeySpec(config.getKey().getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
    }

    public static void main(String[] args) {
        try {
            // 1. 保存加密配置（模拟初始化阶段）
            saveConfig("config.dat");

            // 2. 攻击者替换config.dat为恶意序列化文件（攻击面）
            // 3. 程序正常加载配置并解密
            EncryptionConfig config = loadConfig("config.dat");
            System.out.println("Decrypting with config: " + config.getKey());
            
            // 模拟解密过程（实际应有加密数据）
            String decrypted = decrypt("dummyEncryptedData", config);
            System.out.println("Decrypted: " + decrypted);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}