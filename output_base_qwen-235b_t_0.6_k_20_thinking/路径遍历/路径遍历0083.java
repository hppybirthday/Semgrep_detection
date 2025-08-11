import java.io.*;
import java.util.*;

class Task {
    private String id;
    private String description;
    
    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }
    
    public String getId() {
        return id;
    }
    
    public String getDescription() {
        return description;
    }
}

class TaskManager {
    private Map<String, Task> tasks = new HashMap<>();
    
    public void addTask(Task task) {
        tasks.put(task.getId(), task);
    }
    
    public Task getTask(String id) {
        return tasks.get(id);
    }
}

class FileExporter {
    private String baseExportPath;
    
    public FileExporter(String baseExportPath) {
        this.baseExportPath = baseExportPath;
    }
    
    public void exportTaskDetails(String taskId, String filename) throws IOException {
        // Vulnerable code:直接拼接用户输入
        String exportPath = baseExportPath + "/" + filename;
        File exportFile = new File(exportPath);
        
        // 创建父目录（如果有../路径会自动创建）
        exportFile.getParentFile().mkdirs();
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(exportFile))) {
            TaskManager manager = new TaskManager();
            // 模拟添加测试任务
            manager.addTask(new Task("T001", "完成安全测试"));
            manager.addTask(new Task("T002", "修复漏洞"));
            
            Task task = manager.getTask(taskId);
            if (task != null) {
                writer.write("任务ID: " + task.getId() + "\
");
                writer.write("描述: " + task.getDescription() + "\
");
            } else {
                writer.write("未找到任务: " + taskId);
            }
        }
    }
}

public class VulnerableApp {
    public static void main(String[] args) {
        // 模拟配置
        String baseExportDir = "/var/export/tasks";
        FileExporter exporter = new FileExporter(baseExportDir);
        
        // 模拟用户输入（攻击示例）
        String taskId = "T001";
        String userInput = "../../etc/passwd";  // 攻击载荷
        
        try {
            System.out.println("[+] 尝试导出到路径: " + baseExportDir + "/" + userInput);
            exporter.exportTaskDetails(taskId, userInput);
            System.out.println("[+] 导出成功");
        } catch (Exception e) {
            System.out.println("[!] 导出失败: " + e.getMessage());
        }
    }
}