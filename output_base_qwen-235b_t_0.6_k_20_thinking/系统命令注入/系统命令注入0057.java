package com.bigdata.processing;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 领域实体类
public class DataProcessingTask {
    private String taskId;
    private String dataSource;
    private String processingScript;

    public DataProcessingTask(String taskId, String dataSource, String processingScript) {
        this.taskId = taskId;
        this.dataSource = dataSource;
        this.processingScript = processingScript;
    }

    // 执行脚本处理（存在漏洞的实现）
    public void executeProcessing() {
        try {
            // 构造系统命令
            String command = "python3 " + processingScript + " --input " + dataSource + " --output /tmp/processed_" + taskId;
            System.out.println("Executing command: " + command);
            
            // 危险的命令执行方式
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Getters
    public String getTaskId() { return taskId; }
    public String getDataSource() { return dataSource; }
    public String getProcessingScript() { return processingScript; }
}

// 应用服务类
class ProcessingService {
    public void handleProcessingRequest(String taskId, String dataSource, String scriptPath) {
        DataProcessingTask task = new DataProcessingTask(taskId, dataSource, scriptPath);
        task.executeProcessing();
    }
}

// 主程序入口
public class DataProcessor {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java DataProcessor <task_id> <data_source> <script_path>");
            return;
        }
        
        // 直接使用用户输入参数
        String taskId = args[0];
        String dataSource = args[1];
        String scriptPath = args[2];
        
        ProcessingService service = new ProcessingService();
        service.handleProcessingRequest(taskId, dataSource, scriptPath);
    }
}