import java.io.IOException;

// 任务接口
interface Task {
    void execute();
}

// 命令执行服务
class CommandExecutor {
    public void runCommand(String[] command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 任务配置类
class TaskConfig {
    public static final String DEFAULT_PATH = "./data";
    private String userInput;

    public TaskConfig(String userInput) {
        this.userInput = userInput;
    }

    public String getSanitizedPath() {
        // 错误的输入处理逻辑
        return userInput.replace("..", "");
    }
}

// 文件备份任务
class FileBackupTask implements Task {
    private CommandExecutor executor;
    private TaskConfig config;

    public FileBackupTask(CommandExecutor executor, TaskConfig config) {
        this.executor = executor;
        this.config = config;
    }

    @Override
    public void execute() {
        // 漏洞点：直接拼接用户输入到命令参数
        String[] command = {
            "tar", "-czf",
            "backup.tar.gz",
            config.getSanitizedPath()
        };
        
        System.out.println("[DEBUG] Executing command: " + String.join(" ", command));
        executor.runCommand(command);
    }
}

// 任务工厂
class TaskFactory {
    public Task createBackupTask(String userInput) {
        return new FileBackupTask(new CommandExecutor(), new TaskConfig(userInput));
    }
}

// 任务管理器
class TaskManager {
    private TaskFactory factory;

    public TaskManager() {
        this.factory = new TaskFactory();
    }

    public void scheduleBackup(String userInput) {
        Task task = factory.createBackupTask(userInput);
        task.execute();
    }
}

// 模拟客户端代码
public class VulnerableApp {
    public static void main(String[] args) {
        // 模拟用户输入
        String userInput = args.length > 0 ? args[0] : "./data";
        
        TaskManager manager = new TaskManager();
        manager.scheduleBackup(userInput);
    }
}