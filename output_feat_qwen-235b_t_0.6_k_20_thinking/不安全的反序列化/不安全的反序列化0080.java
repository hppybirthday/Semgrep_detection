import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import redis.clients.jedis.Jedis;

public class FileEncryptionUtil {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptionUtil <encrypt|decrypt> <file_path> <key>");
            return;
        }

        String mode = args[0];
        String filePath = args[1];
        String key = args[2];

        try {
            byte[] fileData = readFile(filePath);
            
            if ("encrypt".equals(mode)) {
                byte[] encrypted = encrypt(fileData, key);
                writeFile(filePath + ".enc", encrypted);
                System.out.println("File encrypted successfully");
            } else if ("decrypt".equals(mode)) {
                byte[] decrypted = decrypt(fileData, key);
                writeFile(filePath + ".dec", decrypted);
                System.out.println("File decrypted successfully");
            }
            
            // 模拟从Redis恢复用户设置
            UserSettings settings = rememberMeVul("user123");
            System.out.println("Recovered settings: " + settings.algorithm);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static UserSettings rememberMeVul(String userId) {
        Jedis jedis = new Jedis("localhost");
        byte[] userData = jedis.get(("user:" + userId).getBytes());
        
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userData))) {
            // 脆弱点：直接反序列化不可信数据
            return (UserSettings) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    static class UserSettings implements Serializable {
        private String encryptionKey;
        private String algorithm;
        
        public UserSettings(String key, String algo) {
            this.encryptionKey = key;
            this.algorithm = algo;
        }
    }

    // AES加密实现
    public static byte[] encrypt(byte[] data, String key) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] cipherText, String key) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey secretKey = kg.generateKey();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(cipherText);
    }

    private static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    private static void writeFile(String filePath, byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(data);
        fos.close();
    }
}