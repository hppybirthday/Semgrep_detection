package com.example.ml.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/jobs")
public class JobConfigController {
    private final JobExecutionService jobService = new JobExecutionService();

    @PostMapping("/schedule")
    public String scheduleJob(@RequestParam String jobId, @RequestParam String modelParams) {
        try {
            // 验证任务ID格式
            if (!jobId.matches("[A-Za-z0-9_\\\\-]{5,20}")) {
                return "Invalid job ID format";
            }
            
            // 处理模型参数
            Map<String, String> params = new LinkedHashMap<>();
            for (String param : modelParams.split("&")) {
                String[] parts = param.split("=");
                if (parts.length == 2) {
                    params.put(parts[0], parts[1]);
                }
            }
            
            // 执行训练任务
            return jobService.executeTrainingJob(jobId, params);
            
        } catch (Exception e) {
            return "Job execution failed: " + e.getMessage();
        }
    }
}

class JobExecutionService {
    String executeTrainingJob(String jobId, Map<String, String> params) throws IOException, InterruptedException {
        // 构建模型训练命令
        StringBuilder cmdBuilder = new StringBuilder("python3 train.py ");
        
        // 添加基础参数
        cmdBuilder.append("--job_id ").append(jobId).append(" ");
        
        // 添加用户自定义参数
        for (Map.Entry<String, String> entry : params.entrySet()) {
            cmdBuilder.append("--").append(entry.getKey()).append(" ").append(entry.getValue()).append(" ");
        }
        
        // 添加日志输出路径
        cmdBuilder.append("2>&1 | tee /var/log/ml_jobs/").append(jobId).append(".log");
        
        // 执行命令
        Process process = Runtime.getRuntime().exec(cmdBuilder.toString());
        process.waitFor();
        
        // 返回执行结果
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