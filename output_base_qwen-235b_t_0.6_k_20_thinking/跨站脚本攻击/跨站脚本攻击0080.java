import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String ENCRYPTION_KEY = "1234567890123456";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入文件描述（将显示在HTML报告中）: ");
        String description = scanner.nextLine();
        
        try {
            System.out.print("输入要加密的文件内容: ");
            String input = scanner.nextLine();
            
            // 加密过程
            byte[] encrypted = encrypt(input, ENCRYPTION_KEY);
            System.out.println("加密成功！");;
            
            // 解密过程
            String decrypted = decrypt(encrypted, ENCRYPTION_KEY);
            System.out.println("解密成功！");
            
            // 生成HTML报告
            generateReport(decrypted, description);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String plainText, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decrypt(byte[] cipherText, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return new String(cipher.doFinal(cipherText));
    }

    private static void generateReport(String content, String description) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
             new FileWriter("report.html"))) {
            writer.write("<html><body>");
            writer.write("<h1>文件解密报告</h1>");
            writer.write("<p>描述: " + description + "</p>");  // 跨站脚本漏洞点
            writer.write("<pre>解密内容: " + content + "</pre>");
            writer.write("</body></html>");
            System.out.println("报告已生成至 report.html");
        }
    }
}