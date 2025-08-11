package com.taskmanager.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

// 领域实体
public class Task {
    private String id;
    private String name;

    public Task(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() { return id; }
    public String getName() { return name; }
}

// 仓储接口
template<interface>
public interface TaskRepository {
    Task findById(String id);
}

// 文件系统实现
public class FileTaskRepository implements TaskRepository {
    private String storagePath;

    public FileTaskRepository(String storagePath) {
        this.storagePath = storagePath;
    }

    @Override
    public Task findById(String id) {
        try {
            // 漏洞点：直接拼接用户输入
            Path path = Paths.get(storagePath + "/" + id + ".task");
            if (!Files.exists(path)) return null;
            
            String content = new String(Files.readAllBytes(path));
            return new Task(id, content.split(",")[0]);
        } catch (Exception e) {
            return null;
        }
    }
}

// 领域服务
public class TaskLogService {
    private TaskRepository taskRepo;

    public TaskLogService(TaskRepository repo) {
        this.taskRepo = repo;
    }

    // 漏洞方法
    public byte[] exportTaskLog(String taskId) throws IOException {
        // 构造危险路径
        String logPath = "./logs/" + taskId + ".log";
        File file = new File(logPath);
        
        // 危险操作：直接读取文件
        if (!file.exists()) throw new IOException("Log not found");
        
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();
        return data;
    }
}

// 恶意测试用例
public class Main {
    public static void main(String[] args) {
        try {
            // 初始化组件
            TaskRepository repo = new FileTaskRepository("/var/data/tasks");
            TaskLogService service = new TaskLogService(repo);
            
            // 模拟正常访问
            System.out.println("Normal access:");
            byte[] normalLog = service.exportTaskLog("task001");
            System.out.println(new String(normalLog));
            
            // 模拟攻击向量
            System.out.println("\
Malicious path traversal attack:");
            byte[] attackLog = service.exportTaskLog("../../../../../etc/passwd");
            System.out.println(new String(attackLog));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}