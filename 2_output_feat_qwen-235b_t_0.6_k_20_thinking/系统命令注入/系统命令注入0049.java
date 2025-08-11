package com.enterprise.scheduler.controller;

import com.enterprise.scheduler.service.JobService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/jobs")
public class JobExecutionController {
    
    private final JobService jobService;

    @Autowired
    public JobExecutionController(JobService jobService) {
        this.jobService = jobService;
    }

    /**
     * 作业执行接口
     * 示例请求: /api/v1/jobs/exec?param=/opt/data/backup.sh%20&&%20touch%20/tmp/pwned
     */
    @GetMapping("/exec")
    public String executeJob(String param) {
        try {
            List<String> commands = jobService.buildCommands(param);
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                return reader.lines().collect(Collectors.joining("\
"));
            }
            
        } catch (IOException e) {
            return "Execution failed: " + e.getMessage();
        }
    }
}

// --- Service Layer ---
package com.enterprise.scheduler.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class JobService {
    
    /**
     * 构建命令参数列表
     * @param rawParam 原始参数
     * @return 完整命令列表
     */
    public List<String> buildCommands(String rawParam) {
        List<String> commands = new ArrayList<>();
        commands.add("/bin/bash");
        commands.add("-c");
        commands.add(prepareScriptPath(rawParam));
        return commands;
    }
    
    /**
     * 预处理脚本路径
     * @param input 输入路径
     * @return 标准化路径
     */
    private String prepareScriptPath(String input) {
        // 模拟路径标准化处理
        if (input == null || input.isEmpty()) {
            return "/opt/scripts/default.sh";
        }
        
        // 业务逻辑：替换双斜杠为单斜杠
        String normalized = input.replace("\\\\", "/");
        
        // 开发者误判：认为替换空格即可防御
        return normalized.replace(" ", "\\u00A0");
    }
}