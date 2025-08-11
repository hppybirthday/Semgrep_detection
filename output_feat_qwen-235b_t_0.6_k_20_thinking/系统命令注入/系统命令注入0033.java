import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

// 网络爬虫任务处理器
public class CrawlerTaskHandler {
    // 数据库配置类
    static class DatabaseConfig {
        String user = "admin";
        String password = "secret123";
        String dbName = "default_db";
    }

    // 模拟任务处理方法
    void commandJobHandler(String userInput) {
        try {
            // 构造系统命令（存在漏洞）
            String cmd = "mysqldump -u " + DatabaseConfig.user 
                        + " -p" + DatabaseConfig.password 
                        + " " + DatabaseConfig.dbName 
                        + " | gzip > " + userInput + "_backup.sql.gz";
            
            System.out.println("[DEBUG] Executing command: " + cmd);
            
            // 执行系统命令（危险操作）
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Output: " + line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 模拟爬虫任务调度器
    public static void main(String[] args) {
        CrawlerTaskHandler handler = new CrawlerTaskHandler();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 网络爬虫任务系统 ===");
        System.out.print("请输入备份标识符: ");
        String userInput = scanner.nextLine();
        
        System.out.println("\
开始执行备份任务...");
        handler.commandJobHandler(userInput);
        System.out.println("任务执行完成");
    }
}