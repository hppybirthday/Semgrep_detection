import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

public class FileEncryptor {
    static class EncryptionParams implements Serializable {
        byte[] iv;
        String algorithm;
        
        EncryptionParams(byte[] iv, String algorithm) {
            this.iv = iv;
            this.algorithm = algorithm;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java FileEncryptor [encrypt|decrypt] [file] [password]");
            return;
        }

        String mode = args[0];
        String filePath = args[1];
        String password = args.length > 3 ? args[3] : "defaultPassword";

        if (mode.equals("encrypt")) {
            encryptFile(filePath, password);
        } else if (mode.equals("decrypt")) {
            decryptFile(filePath, password);
        }
    }

    static void encryptFile(String filePath, String password) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] key = password.getBytes();
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            
            // 保存加密参数到序列化文件
            try (ObjectOutputStream oos = new ObjectOutputStream(
                 new FileOutputStream(filePath + ".params"))) {
                oos.writeObject(new EncryptionParams(iv, "AES/CBC/PKCS5Padding"));
            }

            // 文件加密逻辑（简化处理）
            System.out.println("File encrypted. Encrypted data would be saved in " + filePath + ".enc");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void decryptFile(String filePath, String password) {
        try {
            // 漏洞点：不安全的反序列化
            try (ObjectInputStream ois = new ObjectInputStream(
                 new FileInputStream(filePath + ".params"))) {
                EncryptionParams params = (EncryptionParams) ois.readObject();  // 危险的反序列化
                
                Cipher cipher = Cipher.getInstance(params.algorithm);
                byte[] key = password.getBytes();
                SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(params.iv));
                
                // 解密逻辑（简化处理）
                System.out.println("File decrypted. Decrypted data would be in " + filePath + ".dec");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}