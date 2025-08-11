import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

interface Task {
    String getName();
    String getScriptPath();
}

class CommandTask implements Task {
    private final String name;
    private final String scriptPath;

    public CommandTask(String name, String scriptPath) {
        this.name = name;
        this.scriptPath = scriptPath;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getScriptPath() {
        return scriptPath;
    }
}

class TaskExecutor {
    public void executeTask(Task task) {
        try {
            // 漏洞点：直接拼接用户输入执行系统命令
            Process process = Runtime.getRuntime().exec(
                "bash -c \\"" + task.getScriptPath() + " \\"" + task.getName());
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Output] " + line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public class TaskManager {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java TaskManager <taskName> <scriptPath>");
            return;
        }
        
        // 创建任务（直接使用用户输入）
        Task task = new CommandTask(args[0], args[1]);
        
        // 执行任务
        new TaskExecutor().executeTask(task);
    }
}