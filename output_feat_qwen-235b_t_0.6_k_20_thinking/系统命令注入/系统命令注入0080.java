import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入操作类型(encrypt/decrypt): ");
        String operation = scanner.nextLine();
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        System.out.print("请输入加密密码: ");
        String password = scanner.nextLine();

        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.directory(new File("/tmp"));
            
            if (operation.equalsIgnoreCase("encrypt")) {
                // 构造加密命令（存在漏洞）
                Process process = processBuilder.command("sh", "-c", "openssl enc -aes-256-cbc -in " + filePath + " -out " + filePath + ".enc -k " + password).start();
                process.waitFor();
                System.out.println("加密完成，文件保存为: " + filePath + ".enc");
            } 
            else if (operation.equalsIgnoreCase("decrypt")) {
                // 构造解密命令（存在漏洞）
                Process process = processBuilder.command("sh", "-c", "openssl enc -d -aes-256-cbc -in " + filePath + " -out " + filePath + ".dec -k " + password).start();
                process.waitFor();
                System.out.println("解密完成，文件保存为: " + filePath + ".dec");
            }
            else {
                System.out.println("未知操作类型");
            }
        } 
        catch (IOException | InterruptedException e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }
}