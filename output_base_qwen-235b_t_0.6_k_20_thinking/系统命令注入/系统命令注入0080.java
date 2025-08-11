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
        scanner.nextLine(); // 清除换行符
        
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();
        
        if(choice == 1) {
            encryptFile(filePath, password);
        } else if(choice == 2) {
            decryptFile(filePath, password);
        } else {
            System.out.println("无效的选择!");
        }
    }
    
    private static void encryptFile(String filePath, String password) {
        try {
            // 模拟调用系统加密命令（存在漏洞）
            String cmd = "openssl enc -aes-256-cbc -in " + filePath + 
                        " -pass pass:" + password + " -out " + filePath + ".enc";
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            if(process.waitFor() == 0) {
                System.out.println("加密成功!");
                new File(filePath).delete();
            } else {
                System.err.println("加密失败");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void decryptFile(String filePath, String password) {
        try {
            // 模拟调用系统解密命令（存在漏洞）
            String cmd = "openssl enc -d -aes-256-cbc -in " + filePath + 
                        " -pass pass:" + password + " -out " + filePath.replace(".enc", "");
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            if(process.waitFor() == 0) {
                System.out.println("解密成功!");
                new File(filePath).delete();
            } else {
                System.err.println("解密失败");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}