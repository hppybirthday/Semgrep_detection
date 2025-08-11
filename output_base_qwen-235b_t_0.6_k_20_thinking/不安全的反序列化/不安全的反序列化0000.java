import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        try {
            // 模拟加密存储操作
            EncryptedData data = new EncryptedData("Secret content");
            encryptToFile(data, "data.enc", SECRET_KEY);
            
            // 模拟解密读取操作（存在漏洞）
            System.out.println("Reading encrypted file...");
            EncryptedData decrypted = decryptFromFile("data.enc", SECRET_KEY);
            System.out.println("Decrypted content: " + decrypted.getContent());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void encryptToFile(Object object, String filename, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey.getBytes(), ALGORITHM));
        
        try (FileOutputStream fos = new FileOutputStream(filename);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher);
             ObjectOutputStream oos = new ObjectOutputStream(cos)) {
            oos.writeObject(object);
        }
    }

    public static EncryptedData decryptFromFile(String filename, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey.getBytes(), ALGORITHM));
        
        try (FileInputStream fis = new FileInputStream(filename);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             ObjectInputStream ois = new ObjectInputStream(cis)) {
            
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            
            if (obj instanceof EncryptedData) {
                return (EncryptedData) obj;
            } else {
                throw new ClassCastException("Invalid object type");
            }
        }
    }

    // 可序列化类（可能被攻击利用）
    static class EncryptedData implements Serializable {
        private String content;

        public EncryptedData(String content) {
            this.content = content;
        }

        public String getContent() {
            return content;
        }
    }
}