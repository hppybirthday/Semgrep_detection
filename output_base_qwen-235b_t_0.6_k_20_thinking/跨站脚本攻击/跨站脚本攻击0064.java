import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";
    private static final String LOG_FILE = "operation_log.html";

    public static void main(String[] args) {
        try {
            System.out.println("=== 文件加密工具 ===");
            System.out.print("请输入文件名：");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String fileName = reader.readLine();
            
            // 模拟防御式编程：验证文件存在性
            if (!Files.exists(Paths.get(fileName))) {
                System.out.println("错误：文件不存在");
                return;
            }
            
            String content = new String(Files.readAllBytes(Paths.get(fileName)));
            String encrypted = encrypt(content);
            
            // 漏洞点：未转义用户输入直接写入HTML日志
            String logEntry = "<div>操作记录 - 文件名: " + fileName + ", 加密内容: " + encrypted + "</div>\
";
            Files.write(Paths.get(LOG_FILE), logEntry.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            
            System.out.println("加密完成，结果已记录到日志");
        } catch (Exception e) {
            System.out.println("发生错误：" + e.getMessage());
        }
    }

    private static String encrypt(String value) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 模拟解密方法
    private static String decrypt(String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(decryptedBytes);
    }
}