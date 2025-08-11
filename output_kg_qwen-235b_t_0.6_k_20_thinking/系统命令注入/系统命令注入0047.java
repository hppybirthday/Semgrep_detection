package com.example.logservice.domain.service;

import com.example.logservice.domain.model.LogAnalysisTask;
import com.example.logservice.domain.repository.LogTaskRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
@Slf4j
public class LogAnalysisService {

    private final LogTaskRepository taskRepository;

    public LogAnalysisService(LogTaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    public String processLogFile(String filename) {
        // 模拟从数据库加载任务（实际场景可能包含更多业务逻辑）
        LogAnalysisTask task = taskRepository.findByFilename(filename)
                .orElseThrow(() -> new IllegalArgumentException("Invalid file name"));

        String result = executeLogAnalysisCommand(filename);
        task.markAsProcessed();
        taskRepository.save(task);
        return result;
    }

    private String executeLogAnalysisCommand(String filename) {
        StringBuilder output = new StringBuilder();
        Process process = null;
        
        try {
            // 漏洞点：直接拼接用户输入到命令中
            String command = "cat /var/logs/" + filename + " | grep ERROR";
            log.info("Executing command: {}", command);
            
            // 使用Runtime.exec执行系统命令
            process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }

            int exitCode = process.waitFor();
            log.info("Command exited with code: {}", exitCode);
            
        } catch (Exception e) {
            log.error("Command execution failed", e);
            output.append("Error processing log file: ").append(e.getMessage());
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        
        return output.toString();
    }

    // 模拟领域模型的其他业务方法
    public void validateLogFile(String filename) {
        if (filename == null || filename.isEmpty() || filename.contains("..") || filename.contains("/")) {
            throw new IllegalArgumentException("Invalid file name format");
        }
    }
}

// 模拟领域模型
package com.example.logservice.domain.model;

import java.time.LocalDateTime;

public class LogAnalysisTask {
    private String filename;
    private boolean processed;
    private LocalDateTime createdAt;

    public LogAnalysisTask(String filename) {
        this.filename = filename;
        this.processed = false;
        this.createdAt = LocalDateTime.now();
    }

    public String getFilename() {
        return filename;
    }

    public boolean isProcessed() {
        return processed;
    }

    public void markAsProcessed() {
        this.processed = true;
    }
}

// 模拟仓储接口
package com.example.logservice.domain.repository;

import com.example.logservice.domain.model.LogAnalysisTask;
import java.util.Optional;

public interface LogTaskRepository {
    Optional<LogAnalysisTask> findByFilename(String filename);
    void save(LogAnalysisTask task);
}

// 模拟配置类
package com.example.logservice.infrastructure.config;

import com.example.logservice.domain.repository.LogTaskRepository;
import com.example.logservice.domain.repository.InMemoryLogTaskRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DomainConfig {
    @Bean
    public LogTaskRepository logTaskRepository() {
        return new InMemoryLogTaskRepository();
    }
}

// 模拟内存仓储实现
package com.example.logservice.domain.repository;

import com.example.logservice.domain.model.LogAnalysisTask;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class InMemoryLogTaskRepository implements LogTaskRepository {
    private final Map<String, LogAnalysisTask> tasks = new HashMap<>();

    @Override
    public Optional<LogAnalysisTask> findByFilename(String filename) {
        return Optional.ofNullable(tasks.get(filename));
    }

    @Override
    public void save(LogAnalysisTask task) {
        tasks.put(task.getFilename(), task);
    }
}