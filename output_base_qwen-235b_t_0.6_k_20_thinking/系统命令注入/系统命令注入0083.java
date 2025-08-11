import java.util.*;

// 基类任务
abstract class Task {
    protected String id;
    public Task(String id) { this.id = id; }
    public abstract void execute();
}

// 存在漏洞的备份任务类
class BackupTask extends Task {
    private String backupDir;
    
    public BackupTask(String id, String backupDir) {
        super(id);
        this.backupDir = backupDir;
    }

    @Override
    public void execute() {
        try {
            // 漏洞点：直接拼接用户输入到系统命令
            String cmd = "tar -czf " + id + ".tar.gz " + backupDir;
            System.out.println("[DEBUG] 执行命令: " + cmd);
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            // 简单处理输出流
            Scanner scanner = new Scanner(process.getInputStream());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            
        } catch (Exception e) {
            System.err.println("执行失败: " + e.getMessage());
        }
    }
}

// 任务管理器
class TaskManager {
    private Map<String, Task> tasks = new HashMap<>();

    public void createTask(String id, String dir) {
        tasks.put(id, new BackupTask(id, dir));
    }

    public void runTask(String id) {
        Task task = tasks.get(id);
        if (task != null) {
            task.execute();
        } else {
            System.out.println("任务不存在");
        }
    }
}

// 模拟应用入口
public class VulnerableApp {
    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        
        // 模拟用户输入（正常情况）
        manager.createTask("backup1", "/home/user/docs");
        
        // 模拟攻击者输入（注入命令）
        manager.createTask("malicious", "; rm -rf /tmp/test ||");
        
        System.out.println("=== 执行正常备份 ===");
        manager.runTask("backup1");
        
        System.out.println("\
=== 执行恶意任务 ===");
        manager.runTask("malicious");
    }
}