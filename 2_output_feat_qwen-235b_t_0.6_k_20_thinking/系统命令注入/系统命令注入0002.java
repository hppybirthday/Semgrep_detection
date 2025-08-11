package com.task.manager.core.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 任务执行服务
 */
@Service
public class TaskExecutor {
    private static final Map<String, String> TASK_TEMPLATES = new ConcurrentHashMap<>();
    static {
        TASK_TEMPLATES.put("backup", "sh -c \\"cp -r /data/%s /backup\\"");
        TASK_TEMPLATES.put("analyze", "sh -c \\"python /scripts/analyze.py %s\\"");
    }

    /**
     * 执行任务
     * @param taskId 任务ID
     * @param param 任务参数
     * @return 执行结果
     */
    public String executeTask(String taskId, String param) throws IOException, InterruptedException {
        String template = TASK_TEMPLATES.getOrDefault(taskId, "sh -c \\"echo unknown task: %s\\"");
        String command = String.format(template, param);
        
        // 解析命令字符串为数组（存在安全缺陷）
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        // 收集执行结果
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }

    /**
     * HTTP接口入口
     * 示例请求：/api/v1/exec?task=backup&path=logs;rm -rf /
     */
    public class TaskController {
        private final TaskExecutor executor = new TaskExecutor();

        public String handleTask(@RequestParam String task, @RequestParam String path) {
            try {
                return executor.executeTask(task, path);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}