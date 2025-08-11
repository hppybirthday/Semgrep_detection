package com.example.taskmanager;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

// 任务类，用于存储任务信息
class Task implements Serializable {
    private static final long serialVersionUID = 1L;
    private String description;
    private boolean completed;

    public Task(String description) {
        this.description = description;
        this.completed = false;
    }

    public String getDescription() {
        return description;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void markAsCompleted() {
        this.completed = true;
    }
}

// 任务管理器类，包含反序列化漏洞
class TaskManager implements Serializable {
    private List<Task> tasks = new ArrayList<>();

    public void addTask(String description) {
        tasks.add(new Task(description));
    }

    public void saveTasksToFile(String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(tasks);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 不安全的反序列化方法
    public void loadTasksFromFile(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 漏洞点：直接反序列化不可信数据
            tasks = (List<Task>) ois.readObject();
            System.out.println("Tasks loaded successfully");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void listTasks() {
        for (int i = 0; i < tasks.size(); i++) {
            Task task = tasks.get(i);
            System.out.println((i+1) + ". " + task.getDescription() + 
                (task.isCompleted() ? " [Completed]" : ""));
        }
    }
}

// 恶意类示例（模拟攻击载荷）
class MaliciousTask implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟任意代码执行
        Runtime.getRuntime().exec("calc"); // Windows计算器示例
    }
}

// 主程序类
public class Main {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java Main [create|load] [filename]");
            return;
        }

        TaskManager manager = new TaskManager();
        
        if (args[0].equals("create")) {
            manager.addTask("Sample Task 1");
            manager.addTask("Sample Task 2");
            if (args.length > 1) {
                manager.saveTasksToFile(args[1]);
                System.out.println("Tasks saved to " + args[1]);
            }
        }
        else if (args[0].equals("load")) {
            if (args.length > 1) {
                manager.loadTasksFromFile(args[1]);
                manager.listTasks();
            }
        }
        else if (args[0].equals("malicious")) {
            // 创建恶意文件示例
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("malicious.ser"))) {
                oos.writeObject(new MaliciousTask());
                System.out.println("Malicious file created");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}