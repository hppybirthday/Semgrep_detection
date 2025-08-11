import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * 简单的文件加密解密工具（存在路径遍历漏洞）
 */
public class FileEncryptorDecryptor {
    // 受限目录
    private static final String BASE_DIR = "/safe/storage/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除换行符

        System.out.print("请输入文件名: ");
        String userInput = scanner.nextLine();

        try {
            if (choice == 1) {
                encryptFile(userInput);
            } else if (choice == 2) {
                decryptFile(userInput);
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }

    /**
     * 加密文件（简单异或加密）
     */
    private static void encryptFile(String userInput) throws IOException {
        Path sourcePath = Paths.get(BASE_DIR + userInput);
        Path encryptedPath = Paths.get(BASE_DIR + userInput + ".encrypted");

        // 漏洞点：直接拼接用户输入构造路径
        System.out.println("加密源路径: " + sourcePath);
        System.out.println("加密目标路径: " + encryptedPath);

        if (!isValidPath(sourcePath) || !isValidPath(encryptedPath)) {
            throw new IllegalArgumentException("文件路径不在允许范围内");
        }

        try (FileInputStream fis = new FileInputStream(sourcePath.toFile());
             FileOutputStream fos = new FileOutputStream(encryptedPath.toFile())) {

            int data;
            while ((data = fis.read()) != -1) {
                fos.write(data ^ 0xFF); // 简单异或加密
            }
        }
        System.out.println("加密完成");
    }

    /**
     * 解密文件（简单异或解密）
     */
    private static void decryptFile(String userInput) throws IOException {
        Path encryptedPath = Paths.get(BASE_DIR + userInput);
        Path decryptedPath = Paths.get(BASE_DIR + userInput.replace(".encrypted", ""));

        // 漏洞点：直接拼接用户输入构造路径
        System.out.println("解密源路径: " + encryptedPath);
        System.out.println("解密目标路径: " + decryptedPath);

        if (!isValidPath(encryptedPath) || !isValidPath(decryptedPath)) {
            throw new IllegalArgumentException("文件路径不在允许范围内");
        }

        try (FileInputStream fis = new FileInputStream(encryptedPath.toFile());
             FileOutputStream fos = new FileOutputStream(decryptedPath.toFile())) {

            int data;
            while ((data = fis.read()) != -1) {
                fos.write(data ^ 0xFF); // 简单异或解密
            }
        }
        System.out.println("解密完成");
    }

    /**
     * 验证路径是否在允许范围内（防御式检查不充分）
     */
    private static boolean isValidPath(Path path) throws IOException {
        try {
            // 仅检查路径是否存在和是否为文件
            File file = path.toFile();
            if (!file.exists() || !file.isFile()) {
                return false;
            }
            // 检查路径是否在受限目录内（但未处理路径遍历）
            String canonicalPath = file.getCanonicalPath();
            return canonicalPath.startsWith(new File(BASE_DIR).getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }
}