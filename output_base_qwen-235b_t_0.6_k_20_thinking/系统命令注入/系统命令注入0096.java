import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密工具 ===");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.print("请选择操作(1/2): ");
        
        int choice = Integer.parseInt(scanner.nextLine());
        System.out.print("输入文件路径: ");
        String inputPath = scanner.nextLine();
        System.out.print("输出文件路径: ");
        String outputPath = scanner.nextLine();
        System.out.print("加密密码: ");
        String password = scanner.nextLine();
        
        try {
            ProcessBuilder pb;
            if(choice == 1) {
                // 构造存在漏洞的加密命令
                String[] cmd = {"/bin/sh", "-c", "openssl enc -aes-256-cbc -salt -in '" + inputPath + "' -out '" + outputPath + "' -k '" + password + "'"};
                pb = new ProcessBuilder(cmd);
            } else {
                // 构造存在漏洞的解密命令
                String[] cmd = {"/bin/sh", "-c", "openssl aes-256-cbc -d -in '" + inputPath + "' -out '" + outputPath + "' -k '" + password + "'"};
                pb = new ProcessBuilder(cmd);
            }
            
            // 危险地合并错误流
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("操作完成，退出代码: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}