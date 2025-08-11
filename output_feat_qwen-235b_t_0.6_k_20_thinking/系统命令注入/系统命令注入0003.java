import java.util.ArrayList;
import java.util.List;

// 任务类
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

// 任务管理类
class TaskManager {
    private List<Task> tasks = new ArrayList<>();
    private PdfExportHandler pdfExporter;

    public TaskManager() {
        this.pdfExporter = new PdfExportHandler();
    }

    public void addTask(Task task) {
        tasks.add(task);
    }

    public void exportTasksToPDF(String filePath) {
        String content = "Tasks List:\
";
        for (Task task : tasks) {
            content += task.getId() + ": " + task.getDescription() + "\
";
        }
        
        // 模拟保存到临时文件
        System.out.println("Saving tasks to temp file...");
        // 实际调用外部工具执行PDF转换
        pdfExporter.convertToPDF(filePath);
    }
}

// PDF导出处理器
class PdfExportHandler {
    private CommandExecutor executor = new CommandExecutor();

    public void convertToPDF(String filePath) {
        // 构造命令：magic-pdf 工具 + 用户指定路径
        String command = "magic-pdf " + filePath;
        System.out.println("Executing command: " + command);
        executor.executeCommand(command);
    }
}

// 命令执行器
class CommandExecutor {
    public void executeCommand(String command) {
        try {
            // 漏洞点：直接拼接用户输入执行命令
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            System.out.println("Command executed with exit code: " + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 主程序入口
public class TaskManagementSystem {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java TaskManagementSystem <export_file_path>");
            return;
        }
        
        TaskManager manager = new TaskManager();
        // 添加示例任务
        manager.addTask(new Task("T001", "Fix login bug"));
        manager.addTask(new Task("T002", "Update documentation"));
        
        // 执行导出操作（存在漏洞）
        manager.exportTasksToPDF(args[0]);
    }
}