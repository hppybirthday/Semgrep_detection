import java.io.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {
    private static final String CONFIG_FILE = "config.dat";
    private static final String ENCRYPTED_FILE = "encrypted.dat";

    public static void main(String[] args) {
        try {
            // 模拟首次运行生成配置
            if (!new File(CONFIG_FILE).exists()) {
                EncryptionConfig config = new EncryptionConfig("AES/CBC/PKCS5Padding", generateKey());
                saveConfig(config, CONFIG_FILE);
            }

            // 模拟解密过程（存在漏洞的反序列化）
            EncryptionConfig config = readEncrptionConfig(CONFIG_FILE);
            decryptFile(config, ENCRYPTED_FILE);

        } catch (Exception e) {
            System.err.println("[ERROR] 操作失败: " + e.getMessage());
        }
    }

    static class EncryptionConfig implements Serializable {
        private String transformation;
        private byte[] key;

        public EncryptionConfig(String transformation, byte[] key) {
            this.transformation = transformation;
            this.key = key;
        }

        // 模拟不安全的反序列化入口
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟配置加载后的自动验证（触发漏洞）
            if (transformation.contains("malicious")) {
                Runtime.getRuntime().exec("calc"); // 模拟任意代码执行
            }
        }
    }

    private static void saveConfig(EncryptionConfig config, String filename) throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filename))) {
            out.writeObject(config);
        }
    }

    private static EncryptionConfig readEncrptionConfig(String filename) throws IOException, ClassNotFoundException {
        // 脆弱点：不安全的反序列化操作
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename))) {
            return (EncryptionConfig) in.readObject();
        }
    }

    private static void decryptFile(EncryptionConfig config, String filename) throws Exception {
        SecretKey keySpec = new SecretKeySpec(config.key, "AES");
        Cipher cipher = Cipher.getInstance(config.transformation);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new byte[16]));
        // 模拟解密过程
        System.out.println("[INFO] 使用配置解密文件: " + config.transformation);
    }

    private static byte[] generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }
}