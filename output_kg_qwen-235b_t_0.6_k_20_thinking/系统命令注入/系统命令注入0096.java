import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // 清除缓冲区

        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();

        System.out.print("请输入加密密码: ");
        String password = scanner.nextLine();

        try {
            Process process;
            if (choice == 1) {
                // 使用zip进行加密（原型开发快速实现）
                String command = "zip -P " + password + " encrypted.zip " + filePath;
                System.out.println("执行加密命令: " + command);
                process = Runtime.getRuntime().exec(command);
            } else {
                // 使用unzip进行解密
                String command = "unzip -P " + password + " " + filePath;
                System.out.println("执行解密命令: " + command);
                process = Runtime.getRuntime().exec(command);
            }

            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("输出: " + line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println("错误: " + line);
            }

            int exitCode = process.waitFor();
            System.out.println("操作完成，退出码: " + exitCode);

        } catch (Exception e) {
            System.err.println("发生异常: " + e.getMessage());
            e.printStackTrace();
        }
    }
}