import java.io.IOException;
import java.util.Scanner;

// 领域实体
class Task {
    private String id;
    private String scriptPath;
    private String userInput; // 漏洞点：存储用户输入

    public Task(String id, String scriptPath, String userInput) {
        this.id = id;
        this.scriptPath = scriptPath;
        this.userInput = userInput;
    }

    public String getId() { return id; }
    public String getScriptPath() { return scriptPath; }
    public String getUserInput() { return userInput; }
}

// 领域服务
class TaskService {
    public void executeTask(Task task) {
        try {
            // 漏洞点：直接拼接用户输入到命令中
            String[] cmd = {"/bin/sh", "-c", task.getScriptPath() + " " + task.getUserInput()};
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Process process = pb.start();
            System.out.println("[+] Task executed with exit code " + process.waitFor());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 应用服务
class TaskApplication {
    private TaskService taskService = new TaskService();

    public void handleUserInput(String taskId, String scriptPath, String userInput) {
        Task task = new Task(taskId, scriptPath, userInput);
        taskService.executeTask(task);
    }
}

// 模拟控制器
public class TaskManagementApplication {
    public static void main(String[] args) {
        TaskApplication app = new TaskApplication();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== Task Management System ===");
        System.out.print("Enter Task ID: ");
        String taskId = scanner.nextLine();
        
        System.out.print("Enter Script Path (default: /usr/local/bin/process.sh): ");
        String scriptPath = scanner.nextLine();
        if (scriptPath.isEmpty()) {
            scriptPath = "/usr/local/bin/process.sh";
        }
        
        System.out.print("Enter Processing Parameters: ");
        String userInput = scanner.nextLine();
        
        app.handleUserInput(taskId, scriptPath, userInput);
    }
}