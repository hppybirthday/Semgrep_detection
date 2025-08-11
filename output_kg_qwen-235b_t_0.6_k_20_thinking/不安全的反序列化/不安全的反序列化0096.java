package com.taskmanager.core;

import java.io.*;
import java.util.Base64;

public class TaskManager {
    public static void main(String[] args) {
        TaskService taskService = new TaskServiceImpl();
        TaskController controller = new TaskController(taskService);
        
        // 模拟用户输入（攻击者可控制的恶意输入）
        String maliciousInput = "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eLdJQWxOlTgCAAFMAAR0eXBlcQB+AAJ4cHcQAAAAAQAAAAEAAAAHdAAKRXhlY3V0YWJsZXg=";
        
        try {
            controller.handleLoadRequest(maliciousInput);
        } catch (Exception e) {
            System.err.println("Vulnerable deserialization detected: " + e.getMessage());
        }
    }
}

// 任务接口
interface Task {
    void execute();
}

// 具体任务实现
class ExecutableTask implements Task, Serializable {
    private String command;
    
    public ExecutableTask(String command) {
        this.command = command;
    }
    
    @Override
    public void execute() {
        try {
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 任务存储类
class TaskStorage {
    // 不安全的反序列化方法
    public Task loadTask(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (Task) ois.readObject(); // 漏洞点：直接反序列化不可信数据
        }
    }
    
    public byte[] saveTask(Task task) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(task);
            return bos.toByteArray();
        }
    }
}

// 任务服务接口
interface TaskService {
    void processTask(String taskData);
}

// 任务服务实现
class TaskServiceImpl implements TaskService {
    private TaskStorage storage = new TaskStorage();
    
    @Override
    public void processTask(String taskData) {
        try {
            byte[] decoded = Base64.getDecoder().decode(taskData);
            Task task = storage.loadTask(decoded);
            task.execute();
        } catch (Exception e) {
            throw new RuntimeException("Task processing failed", e);
        }
    }
}

// 任务控制器
class TaskController {
    private TaskService taskService;
    
    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }
    
    public void handleLoadRequest(String taskData) {
        taskService.processTask(taskData);
    }
}