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
        scanner.nextLine(); // 消耗换行符

        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        
        System.out.print("请输入加密密码: ");
        String password = scanner.nextLine();
        
        try {
            if (choice == 1) {
                encryptFile(filePath, password);
            } else if (choice == 2) {
                decryptFile(filePath, password);
            } else {
                System.out.println("无效的选择");
            }
        } catch (Exception e) {
            System.out.println("操作失败: " + e.getMessage());
        }
    }

    private static void encryptFile(String filePath, String password) throws IOException {
        String command = String.format("openssl enc -aes-256-cbc -in \\"%s\\" -k %s -out encrypted.file", 
                    filePath, password);
        executeCommand(command);
    }

    private static void decryptFile(String filePath, String password) throws IOException {
        String command = String.format("openssl enc -d -aes-256-cbc -in \\"%s\\" -k %s -out decrypted.file", 
                    filePath, password);
        executeCommand(command);
    }

    private static void executeCommand(String command) throws IOException {
        System.out.println("执行命令: " + command);
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        
        try {
            int exitCode = process.waitFor();
            System.out.println("命令执行结束，退出码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}