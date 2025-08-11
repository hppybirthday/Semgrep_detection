import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class FileEncryptionTool {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptionTool <encrypt|decrypt> <inputFile> <outputFile>");
            return;
        }

        String operation = args[0];
        String inputFile = args[1];
        String outputFile = args[2];

        try {
            if (operation.equalsIgnoreCase("encrypt")) {
                encryptFile(inputFile, outputFile);
            } else if (operation.equalsIgnoreCase("decrypt")) {
                decryptFile(inputFile, outputFile);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error during operation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(outputFile), cipher)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    private static void decryptFile(String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             ObjectInputStream ois = new ObjectInputStream(cis)) {
            
            Object obj = ois.readObject(); // 不安全的反序列化漏洞点
            System.out.println("Decrypted object: " + obj);
            
            // 模拟保存解密后的对象
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(obj.toString().getBytes());
            }
        }
    }

    // 模拟可序列化的数据类
    public static class User implements Serializable {
        private String username;
        private String password;

        public User(String username, String password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public String toString() {
            return "User{username='" + username + "', password='" + password + "'}";
        }
    }
}