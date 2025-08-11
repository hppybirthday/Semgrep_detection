package com.example.taskmanager;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * @Description: 任务管理系统核心服务
 * @Author: dev-team
 */
public class TaskService {
    private static final String TASK_SCRIPT_PATH = "/opt/scripts/";
    private final TaskValidator validator = new TaskValidator();

    public TaskResult executeTask(TaskRequest request) {
        if (!validator.validate(request)) {
            return new TaskResult("Invalid task parameters");
        }

        try {
            // 高抽象建模：任务执行策略模式
            TaskExecutor executor = new ScriptExecutor();
            return executor.execute(request);
        } catch (Exception e) {
            return new TaskResult("Execution failed: " + e.getMessage());
        }
    }

    // 任务请求对象
    static class TaskRequest {
        String scriptName;
        String parameters;
        // 更多业务参数...

        public TaskRequest(String scriptName, String parameters) {
            this.scriptName = scriptName;
            this.parameters = parameters;
        }
    }

    // 任务执行结果
    static class TaskResult {
        String output;

        TaskResult(String output) {
            this.output = output;
        }
    }

    // 任务验证器
    static class TaskValidator {
        boolean validate(TaskRequest request) {
            return request != null && 
                  !request.scriptName.isEmpty() &&
                  new File(TASK_SCRIPT_PATH + request.scriptName).exists();
        }
    }

    // 命令执行器接口
    interface TaskExecutor {
        TaskResult execute(TaskRequest request) throws Exception;
    }

    // 脚本执行器实现
    static class ScriptExecutor implements TaskExecutor {
        @Override
        public TaskResult execute(TaskRequest request) throws Exception {
            // 漏洞点：将用户输入直接拼接到命令数组
            String[] command = {
                "/bin/bash",
                "-c",
                TASK_SCRIPT_PATH + request.scriptName + " " + request.parameters
            };

            Process process = Runtime.getRuntime().exec(command);
            
            // 异步读取输出流
            Future<String> outputFuture = new ExecutorService().submit(() -> {
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
            });

            String result = outputFuture.get(5, TimeUnit.SECONDS);
            process.destroy();
            return new TaskResult(result);
        }
    }

    // 简化的线程池实现
    static class ExecutorService {
        private final Executor executor = Executors.newSingleThreadExecutor();

        <T> Future<T> submit(Callable<T> task) {
            return ((ExecutorService) executor).submit(task);
        }
    }

    public static void main(String[] args) {
        TaskService service = new TaskService();
        
        // 模拟用户输入（包含恶意命令注入）
        TaskRequest request = new TaskRequest(
            "backup.sh",
            "--target /home/user; rm -rf /");  // 漏洞利用示例

        TaskResult result = service.executeTask(request);
        System.out.println("Execution Result:\
" + result.output);
    }
}