package com.example.taskmanager;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class TaskManager {
    private static final String BASE_DIR = "./user_tasks/";
    private List<Task> tasks = new ArrayList<>();

    public void addTask(Task task) {
        tasks.add(task);
    }

    public void exportTasksToFile(String filename) {
        try {
            // 漏洞点：直接拼接用户输入的文件名
            Path targetPath = Paths.get(BASE_DIR + filename);
            File targetFile = targetPath.toFile();
            
            // 创建父目录（可能创建任意路径）
            if (!targetFile.getParentFile().exists()) {
                targetFile.getParentFile().mkdirs();
            }
            
            // 创建文件并写入任务数据
            if (!targetFile.exists()) {
                targetFile.createNewFile();
            }
            
            try (FileWriter writer = new FileWriter(targetFile)) {
                for (Task task : tasks) {
                    writer.write(task.toString() + "\
");
                }
            }
            
            System.out.println("任务导出成功到: " + targetFile.getAbsolutePath());
            
        } catch (IOException e) {
            System.err.println("导出任务失败: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        
        // 添加示例任务
        manager.addTask(new Task("T001", "完成报告", "高"));
        manager.addTask(new Task("T002", "代码审查", "中"));
        
        // 模拟用户输入（攻击者可能传入包含../的路径）
        if (args.length > 0) {
            manager.exportTasksToFile(args[0]);
        } else {
            manager.exportTasksToFile("tasks.txt");
        }
    }
}

class Task {
    private String id;
    private String description;
    private String priority;

    public Task(String id, String description, String priority) {
        this.id = id;
        this.description = description;
        this.priority = priority;
    }

    @Override
    public String toString() {
        return String.format("任务ID: %s | 描述: %s | 优先级: %s", id, description, priority);
    }
}