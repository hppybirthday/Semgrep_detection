import java.io.*;
import java.util.Scanner;

/**
 * 任务管理系统核心类
 * 存在系统命令注入漏洞的示例实现
 */
public class TaskManager {
    
    /**
     * 执行系统命令
     * @param command 待执行的命令
     * @throws IOException
     */
    public void executeCommand(String command) throws IOException {
        // 模拟执行系统命令进行任务处理
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[命令输出] " + line);
        }
        
        // 等待命令执行完成
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行中断", e);
        }
    }
    
    /**
     * 备份任务数据到指定路径
     * @param backupPath 备份目标路径
     * @throws IOException
     */
    public void backupTasks(String backupPath) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令中
        String command = "tar -czf " + backupPath + " /var/tasks/";
        executeCommand(command);
    }
    
    /**
     * 恢复任务数据
     * @param archivePath 归档文件路径
     * @throws IOException
     */
    public void restoreTasks(String archivePath) throws IOException {
        // 漏洞点：未验证输入直接拼接到命令参数中
        String[] cmdArray = {"sh", "-c", "tar -xzf " + archivePath + " -C /var/tasks/"};
        executeCommand(String.join(" ", cmdArray));
    }
    
    /**
     * 主程序入口
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 任务管理系统 ===");
        System.out.println("1. 备份任务数据");
        System.out.println("2. 恢复任务数据");
        System.out.print("请选择操作: ");
        
        int choice = scanner.nextInt();
        scanner.nextLine(); // 消耗换行符
        
        try {
            if (choice == 1) {
                System.out.print("请输入备份路径: ");
                String path = scanner.nextLine();
                manager.backupTasks(path);
                System.out.println("备份完成");
            } else if (choice == 2) {
                System.out.print("请输入归档文件路径: ");
                String path = scanner.nextLine();
                manager.restoreTasks(path);
                System.out.println("恢复完成");
            } else {
                System.out.println("无效的选择");
            }
        } catch (IOException e) {
            System.err.println("操作失败: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }
}