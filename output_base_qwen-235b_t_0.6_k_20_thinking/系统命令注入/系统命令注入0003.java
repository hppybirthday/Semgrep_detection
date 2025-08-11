import java.util.*;
import java.io.*;

class Task {
    private String id;
    private String description;
    
    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }
    
    public String getId() { return id; }
    public String getDescription() { return description; }
}

class TaskManager {
    private Map<String, Task> tasks = new HashMap<>();
    
    public void addTask(Task task) {
        tasks.put(task.getId(), task);
    }
    
    public void displayTasks() {
        System.out.println("\
Current Tasks:");
        tasks.forEach((id, task) -> 
            System.out.println("ID: " + id + ", Description: " + task.getDescription()));
    }
}

class ExportManager {
    public void exportTasksToFile(Map<String, Task> tasks) {
        try {
            System.out.print("Enter filename to export: ");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in));
            String filename = reader.readLine();
            
            // 漏洞点：直接拼接用户输入构造系统命令
            StringBuilder content = new StringBuilder();
            tasks.forEach((id, task) -> 
                content.append(id).append(",").append(task.getDescription()).append("\
"));
            
            // 不安全的命令构造方式
            String command = String.format("echo \\"%s\\" > %s", content.toString(), filename);
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            int exitCode = process.waitFor();
            System.out.println(exitCode == 0 ? "Export successful!" : "Export failed");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public class TaskSystem {
    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        ExportManager exporter = new ExportManager();
        
        // 初始化示例任务
        manager.addTask(new Task("001", "Complete project proposal"));
        manager.addTask(new Task("002", "Review team code"));
        
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\
=== Task Management System ===");
            System.out.println("1. View Tasks");
            System.out.println("2. Export Tasks");
            System.out.println("3. Exit");
            System.out.print("Choose option (1-3): ");
            
            try {
                int choice = Integer.parseInt(scanner.nextLine());
                switch (choice) {
                    case 1:
                        manager.displayTasks();
                        break;
                    case 2:
                        exporter.exportTasksToFile(manager.getTasks());
                        break;
                    case 3:
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option");
                }
            } catch (NumberFormatException e) {
                System.out.println("Please enter a valid number");
            }
        }
    }
}

// 注意：需要为TaskManager添加getTasks方法
// 修改TaskManager类增加：
// public Map<String, Task> getTasks() { return tasks; }