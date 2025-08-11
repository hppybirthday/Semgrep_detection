import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class FileCrypt {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final byte[] KEY = "MySecretKey12345".getBytes();

    public static void encryptFile(String filePath, String outputPath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, ALGORITHM));
        
        try (FileInputStream inputStream = new FileInputStream(filePath);
             CipherOutputStream cipherOutputStream = new CipherOutputStream(
                 new FileOutputStream(outputPath), cipher)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void decryptFile(String filePath, String outputPath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, ALGORITHM));
        
        try (CipherInputStream cipherInputStream = new CipherInputStream(
                 new FileInputStream(filePath), cipher);
             FileOutputStream outputStream = new FileOutputStream(outputPath)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("=== 文件加密解密工具 ===");
            System.out.println("1. 加密文件");
            System.out.println("2. 解密文件");
            System.out.print("请选择操作(1/2): ");
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in));
            
            String choice = reader.readLine();
            System.out.print("请输入文件路径: ");
            String filePath = reader.readLine();
            System.out.print("请输入目标路径: ");
            String outputPath = reader.readLine();
            
            if ("1".equals(choice)) {
                encryptFile(filePath, outputPath);
                System.out.println("加密完成");
            } else if ("2".equals(choice)) {
                decryptFile(filePath, outputPath);
                System.out.println("解密完成");
            }
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}