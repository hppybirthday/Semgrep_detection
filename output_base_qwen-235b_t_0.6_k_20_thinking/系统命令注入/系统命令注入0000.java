import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作(1/2): ");
        String choice = scanner.nextLine();

        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();

        System.out.print("请输入密码: ");
        String password = scanner.nextLine();

        try {
            if (choice.equals("1")) {
                encryptFile(filePath, password);
            } else if (choice.equals("2")) {
                decryptFile(filePath, password);
            } else {
                System.out.println("无效的选择");
            }
        } catch (Exception e) {
            System.out.println("发生错误: " + e.getMessage());
        }
    }

    private static void encryptFile(String filePath, String password) throws IOException {
        String command = "openssl enc -aes-256-cbc -salt -in " + filePath + " -out " + filePath + ".enc -k " + password;
        System.out.println("执行加密命令: " + command);
        executeCommand(command);
    }

    private static void decryptFile(String filePath, String password) throws IOException {
        String command = "openssl enc -d -aes-256-cbc -in " + filePath + " -out " + filePath.replace(".enc", "") + " -k " + password;
        System.out.println("执行解密命令: " + command);
        executeCommand(command);
    }

    private static void executeCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("输出: " + line);
        }
        while ((line = errorReader.readLine()) != null) {
            System.out.println("错误: " + line);
        }
    }
}