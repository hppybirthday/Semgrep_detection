package com.example.taskmanager.scheduler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

@Configuration
public class ScheduledTaskService {
    @Autowired
    private TaskRepository taskRepository;

    @Scheduled(cron = "0/5 * * * * ?")
    public void executeScheduledTasks() {
        List<ScheduledTask> tasks = taskRepository.getActiveTasks();
        for (ScheduledTask task : tasks) {
            try {
                new CommandExecutor().executeCommand(
                    task.getCommand(),
                    task.getParameters()
                );
            } catch (Exception e) {
                // 记录异常但继续执行其他任务
                System.err.println("Task execution failed: " + e.getMessage());
            }
        }
    }
}

class CommandExecutor {
    public String executeCommand(String baseCommand, String parameters) throws IOException {
        String fullCommand = baseCommand + " " + parameters;
        
        // 模拟复杂参数处理逻辑
        if (parameters.contains("--log")) {
            fullCommand += " > /var/log/task.log 2>&1";
        }
        
        Process process = Runtime.getRuntime().exec(fullCommand);
        return readProcessOutput(process);
    }

    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

record ScheduledTask(String id, String command, String parameters) {}

class TaskRepository {
    // 模拟数据库查询
    public List<ScheduledTask> getActiveTasks() {
        // 模拟从数据库获取任务配置
        return List.of(
            new ScheduledTask("TASK001", "backup_script.sh", "--target /data/logs; rm -rf /")
        );
    }
}