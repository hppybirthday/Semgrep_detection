import java.io.*;
import java.nio.file.*;
import java.util.*;

// 模拟大数据处理中的日志分析组件
class LogAnalyzer {
    private final String baseDir;

    public LogAnalyzer(String baseDir) {
        this.baseDir = baseDir;
    }

    // 漏洞点：未验证用户输入的文件名
    public void analyzeLog(String userInput) throws IOException {
        String filePath = baseDir + "/" + userInput;
        File file = new File(filePath);
        
        if (!file.exists()) {
            System.out.println("日志文件不存在: " + userInput);
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null) {
                // 模拟日志处理逻辑
                if (line.contains("ERROR")) {
                    lineCount++;
                }
            }
            System.out.println("发现 " + lineCount + " 个错误日志条目");
        }
    }
}

// 模拟分布式任务调度器
class TaskScheduler {
    private final List<String> pendingTasks = new ArrayList<>();

    public void addTask(String taskName) {
        pendingTasks.add(taskName);
    }

    public void processTasks(LogAnalyzer analyzer) {
        for (String task : pendingTasks) {
            try {
                System.out.println("开始处理任务: " + task);
                analyzer.analyzeLog(task);
                System.out.println("任务完成: " + task);
            } catch (Exception e) {
                System.err.println("任务失败: " + e.getMessage());
            }
        }
    }
}

public class Main {
    public static void main(String[] args) {
        // 初始化系统配置
        String storagePath = "/var/data/logs";
        LogAnalyzer analyzer = new LogAnalyzer(storagePath);
        TaskScheduler scheduler = new TaskScheduler();

        // 模拟接收外部输入
        if (args.length > 0) {
            // 危险：直接使用用户输入作为文件名
            scheduler.addTask(args[0]);
        } else {
            scheduler.addTask("app.log");
        }

        // 执行任务处理
        scheduler.processTasks(analyzer);
    }
}