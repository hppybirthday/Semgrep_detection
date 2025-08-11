package com.taskmanager.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * @Description: 任务管理系统核心模块
 * @Author: security_expert
 * @Date: 2024/4/15 15:00
 */
public class TaskManager {
    private static final Logger logger = Logger.getLogger(TaskManager.class.getName());
    private final TaskExecutor taskExecutor;

    public TaskManager() {
        this.taskExecutor = new CommandTaskExecutor();
    }

    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        try {
            // 模拟用户输入："backup123; rm -rf /tmp/*"
            manager.executeTask("backupTask", new String[]{args[0]});
        } catch (Exception e) {
            logger.severe("任务执行失败: " + e.getMessage());
        }
    }

    public void executeTask(String taskType, String[] params) throws IOException {
        taskExecutor.execute(taskType, params);
    }
}

interface TaskExecutor {
    void execute(String taskType, String[] params) throws IOException;
}

class CommandTaskExecutor implements TaskExecutor {
    @Override
    public void execute(String taskType, String[] params) throws IOException {
        List<String> command = new ArrayList<>();
        
        switch (taskType) {
            case "backupTask":
                // 构造备份命令：tar -czf [用户输入].tar.gz /data/tasks/[用户输入]
                command.add("tar");
                command.add("-czf");
                command.add(params[0] + ".tar.gz");
                command.add("/data/tasks/" + params[0]);
                break;
            case "syncTask":
                command.add("rsync");
                command.add("-avz");
                command.add(params[0]);
                break;
            default:
                throw new IllegalArgumentException("未知任务类型: " + taskType);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[输出] " + line);
        }
        
        int exitCode = process.waitFor();
        System.out.println("任务执行结束，退出码: " + exitCode);
    }
}

abstract class BaseTask {
    protected String taskId;
    protected TaskPriority priority;
    
    public BaseTask(String taskId, TaskPriority priority) {
        this.taskId = taskId;
        this.priority = priority;
    }
    
    public abstract void run() throws IOException;
}

enum TaskPriority {
    LOW, MEDIUM, HIGH
}
