import java.util.Scanner;
import java.io.IOException;

public class TaskManager {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 任务管理系统 ===");
        System.out.print("请输入备份脚本路径: ");
        String scriptPath = scanner.nextLine();
        
        // 声明式任务配置（模拟Spring配置风格）
        TaskConfig config = new TaskConfig();
        config.setScriptPath(scriptPath);
        
        // 执行备份任务
        BackupTask task = new BackupTask(config);
        task.execute();
    }
}

class TaskConfig {
    private String scriptPath;
    
    public void setScriptPath(String scriptPath) {
        this.scriptPath = scriptPath;
    }
    
    public String getScriptPath() {
        return scriptPath;
    }
}

class BackupTask {
    private TaskConfig config;
    
    public BackupTask(TaskConfig config) {
        this.config = config;
    }
    
    public void execute() {
        try {
            // 存在漏洞的命令执行方式
            String command = "bash -c \\"" + config.getScriptPath() + "\\"";
            System.out.println("正在执行命令: " + command);
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取错误流
            StreamGobbler errorGobbler = new StreamGobbler(
                process.getErrorStream(), "ERROR");
            // 读取输入流
            StreamGobbler outputGobbler = new StreamGobbler(
                process.getInputStream(), "OUTPUT");
            
            errorGobbler.run();
            outputGobbler.run();
            
            int exitCode = process.waitFor();
            System.out.println("命令执行结束，退出码: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class StreamGobbler implements Runnable {
    private java.io.InputStream is;
    private String type;
    
    public StreamGobbler(java.io.InputStream is, String type) {
        this.is = is;
        this.type = type;
    }
    
    public void run() {
        try {
            java.io.InputStreamReader isr = new java.io.InputStreamReader(is);
            java.io.BufferedReader br = new java.io.BufferedReader(isr);
            String line = null;
            while ((line = br.readLine()) != null) {
                System.out.println(type + ": " + line);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
}