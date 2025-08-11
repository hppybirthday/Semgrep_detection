import java.io.*;
import java.util.Scanner;

/**
 * 文件加密解密工具（存在系统命令注入漏洞）
 * 快速原型开发风格，直接拼接用户输入到系统命令
 */
public class FileCryptoTool {
    
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
            if("1".equals(choice)) {
                encryptFile(filePath, password);
            } else if("2".equals(choice)) {
                decryptFile(filePath, password);
            } else {
                System.out.println("无效的选择");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }

    /**
     * 使用openssl进行AES加密（存在命令注入漏洞）
     */
    private static void encryptFile(String filePath, String password) throws IOException {
        String command = String.format("openssl enc -aes-256-cbc -in %s -out %s.enc -pass pass:%s", 
                    filePath, filePath, password);
        
        System.out.println("执行加密命令: " + command);
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取错误流防止阻塞
        new StreamGobbler(process.getErrorStream()).start();
        
        try {
            int exitCode = process.waitFor();
            System.out.println("加密完成，退出码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 使用openssl进行AES解密（存在命令注入漏洞）
     */
    private static void decryptFile(String filePath, String password) throws IOException {
        String encryptedFile = filePath + ".enc";
        String command = String.format("openssl enc -d -aes-256-cbc -in %s -out %s.dec -pass pass:%s", 
                    encryptedFile, filePath, password);
        
        System.out.println("执行解密命令: " + command);
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取错误流防止阻塞
        new StreamGobbler(process.getErrorStream()).start();
        
        try {
            int exitCode = process.waitFor();
            System.out.println("解密完成，退出码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 流读取线程防止缓冲区阻塞
     */
    static class StreamGobbler extends Thread {
        private InputStream is;

        public StreamGobbler(InputStream is) {
            this.is = is;
        }

        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null) {
                    // 消耗输出流
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}