package com.example.taskmanager;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * 任务实体类
 */
public class Task {
    private String id;
    private String description;
    private String filePath; // 用户可控的文件路径参数

    public Task(String id, String description, String filePath) {
        this.id = id;
        this.description = description;
        this.filePath = filePath;
    }

    public String getId() { return id; }
    public String getDescription() { return description; }
    public String getFilePath() { return filePath; }
}

/**
 * 任务服务抽象类
 */
abstract class TaskService {
    protected abstract void processTask(Task task) throws IOException;
}

/**
 * 文件任务服务实现类
 * 存在路径遍历漏洞的实现
 */
public class FileTaskService extends TaskService {
    // 模拟受限的文件存储目录
    private static final String BASE_DIR = "/var/task_data/";

    @Override
    protected void processTask(Task task) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        File targetFile = new File(BASE_DIR + task.getFilePath());
        
        // 模拟写入任务描述到文件
        try (FileWriter writer = new FileWriter(targetFile)) {
            writer.write("[Task ID: " + task.getId() + "]\
");
            writer.write(task.getDescription());
        }
        
        System.out.println("Task processed: " + targetFile.getAbsolutePath());
    }

    /**
     * 模拟攻击场景：通过构造特殊路径访问敏感文件
     * 示例输入："../../../../../etc/passwd"
     */
    public static void main(String[] args) {
        try {
            TaskService service = new FileTaskService();
            
            // 模拟用户输入（攻击载荷）
            Task maliciousTask = new Task(
                "T001",
                "恶意任务描述",
                "../../../../../etc/passwd"
            );
            
            // 触发漏洞
            service.processTask(maliciousTask);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}