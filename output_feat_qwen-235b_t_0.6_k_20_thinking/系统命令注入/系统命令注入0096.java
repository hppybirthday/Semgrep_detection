import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入操作类型(encrypt/decrypt): ");
        String operation = scanner.nextLine();
        
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();
        
        if (operation.equalsIgnoreCase("encrypt")) {
            encryptFile(filePath, password);
        } else if (operation.equalsIgnoreCase("decrypt")) {
            decryptFile(filePath, password);
        } else {
            System.out.println("无效的操作类型");
        }
    }

    private static void encryptFile(String filePath, String password) {
        try {
            // 漏洞点：直接拼接用户输入到系统命令中
            String cmd = "/bin/sh -c openssl enc -aes-256-cbc -in \\"" + filePath + "\\" -out \\"" + filePath + ".enc\\" -k \\"" + password + "\\"";
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("加密输出: " + line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println("加密错误: " + line);
            }
            
            process.waitFor();
            System.out.println("加密完成");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void decryptFile(String filePath, String password) {
        try {
            // 漏洞点：直接拼接用户输入到系统命令中
            String cmd = "/bin/sh -c openssl enc -d -aes-256-cbc -in \\"" + filePath + "\\" -out \\"" + filePath.replace(".enc", "") + "\\" -k \\"" + password + "\\"";
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("解密输出: " + line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println("解密错误: " + line);
            }
            
            process.waitFor();
            System.out.println("解密完成");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}