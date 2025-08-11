import java.io.*;
import java.util.Scanner;

class CommandExecutor {
    public void executeCommand(String taskName) throws IOException {
        // 模拟调用Windows批处理文件执行备份操作
        String command = "cmd /c backup_script.bat " + taskName;
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[STDOUT] " + line);
        }
        while ((line = errorReader.readLine()) != null) {
            System.err.println("[STDERR] " + line);
        }
        
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

class TaskManager {
    private CommandExecutor executor = new CommandExecutor();
    
    public void scheduleTask(String userInput) {
        try {
            // 直接使用用户输入作为任务名称参数
            executor.executeCommand(userInput);
        } catch (IOException e) {
            System.err.println("任务执行失败: " + e.getMessage());
        }
    }
}

class TaskConfiguration {
    public String getTaskNameFromUser() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入任务名称: ");
        return scanner.nextLine();
    }
}

public class TaskSystem {
    public static void main(String[] args) {
        System.out.println("=== 任务管理系统 v1.0 ===");
        TaskConfiguration config = new TaskConfiguration();
        TaskManager manager = new TaskManager();
        
        // 模拟定时任务配置流程
        String taskName = config.getTaskNameFromUser();
        System.out.println("正在执行任务: " + taskName);
        manager.scheduleTask(taskName);
        
        System.out.println("任务执行完成");
    }
}
// 模拟的backup_script.bat内容（实际系统中存在）:
// @echo off
// echo 正在备份任务: %1
// ping 127.0.0.1 -n 2 >nul