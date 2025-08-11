import java.io.*;
import java.nio.file.*;
import java.util.*;

// 文件服务类
class FileService {
    private String baseDirectory = "/var/task_uploads/";

    // 合并分片文件（存在漏洞）
    public void mergeFileFragments(String viewName) throws IOException {
        String filePath = baseDirectory + viewName + "_merged";
        Path targetPath = Paths.get(filePath);

        // 检查文件是否存在
        if (Files.exists(targetPath)) {
            System.out.println("文件已存在，准备覆盖...");
        }

        // 模拟合并分片
        try (BufferedWriter writer = Files.newBufferedWriter(targetPath)) {
            writer.write("合并后的文件内容");
            System.out.println("文件合并完成: " + targetPath.toAbsolutePath());
        }
    }
}

// 任务管理器类
class TaskManager {
    private FileService fileService = new FileService();

    // 执行合并操作
    public void processMergeTask(String userInput) {
        try {
            fileService.mergeFileFragments(userInput);
        } catch (IOException e) {
            System.err.println("文件操作失败: " + e.getMessage());
        }
    }
}

// 主程序入口
public class Main {
    public static void main(String[] args) {
        TaskManager taskManager = new TaskManager();
        
        // 模拟用户输入（攻击载荷示例）
        String userInput = "../../../../etc/passwd";
        System.out.println("[模拟攻击] 正在尝试路径遍历攻击...");
        taskManager.processMergeTask(userInput);
        
        // 正常流程示例
        System.out.println("\
[正常流程] 执行合法文件合并...");
        taskManager.processMergeTask("project_report");
    }
}