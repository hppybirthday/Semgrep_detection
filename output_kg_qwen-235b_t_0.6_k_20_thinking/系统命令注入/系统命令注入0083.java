import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 任务管理系统 - 存在系统命令注入漏洞的示例
 */
class Task {
    private String name;
    private String parameter;

    public Task(String name, String parameter) {
        this.name = name;
        this.parameter = parameter;
    }

    public String getName() {
        return name;
    }

    public String getParameter() {
        return parameter;
    }
}

class CommandExecutor {
    public String executeCommand(String command) throws IOException {
        // 模拟执行系统命令的危险实现
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

public class TaskManager {
    private CommandExecutor executor;

    public TaskManager() {
        this.executor = new CommandExecutor();
    }

    public String processTask(Task task) {
        try {
            // 危险的命令拼接方式
            String command = "echo 'Processing task: " + task.getName() + "' && ";
            // 漏洞点：直接将用户参数拼接到命令中
            command += "cat /tasks/" + task.getParameter();
            
            return executor.executeCommand(command);
        } catch (IOException e) {
            return "Error executing task: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        // 模拟用户输入
        TaskManager manager = new TaskManager();
        
        // 正常使用示例
        System.out.println("--- 正常使用 ---");
        Task normalTask = new Task("backup", "config.txt");
        System.out.println(manager.processTask(normalTask));
        
        // 恶意输入示例（系统命令注入）
        System.out.println("\
--- 恶意输入攻击 ---");
        Task maliciousTask = new Task("delete", "dummy.txt; rm -rf /");
        System.out.println(manager.processTask(maliciousTask));
    }
}