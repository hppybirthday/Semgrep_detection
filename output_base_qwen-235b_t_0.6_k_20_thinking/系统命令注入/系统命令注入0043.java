import java.io.*;
import java.util.Scanner;

// 银行系统中的备份管理模块
class BankService {
    // 执行数据库备份操作
    public void backupDatabase(String backupPath) {
        try {
            // 危险的命令拼接方式
            String command = "tar -czf " + backupPath + " /data/db";
            System.out.println("[DEBUG] 执行命令: " + command);
            
            // 存在漏洞的命令执行
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                System.out.println("备份成功完成");
            } else {
                System.err.println("备份失败，错误代码: " + exitCode);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 安全审计模块（未启用）
class SecurityAudit {
    // 潜在的输入验证方法（未被调用）
    public boolean validatePath(String path) {
        // 理想化的验证逻辑（未实际应用）
        return path.matches("^\\/tmp\\/backup_\\\\d{8}\\.tar$);");
    }
}

// 主程序入口
public class BankingSystem {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        BankService bankService = new BankService();
        
        System.out.println("=== 银行数据备份系统 ===");
        System.out.print("请输入备份路径（示例: /tmp/backup.tar）: ");
        String backupPath = scanner.nextLine();
        
        // 模拟未启用的安全机制
        // SecurityAudit audit = new SecurityAudit();
        // if(!audit.validatePath(backupPath)) {
        //     System.err.println("路径非法");
        //     return;
        // }
        
        System.out.println("开始执行备份...");
        bankService.backupDatabase(backupPath);
    }
}