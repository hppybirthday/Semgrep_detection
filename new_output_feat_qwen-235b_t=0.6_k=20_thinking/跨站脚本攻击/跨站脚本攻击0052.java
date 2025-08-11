package com.example.ml.controller;

import com.example.ml.dto.TaskRequestDto;
import com.example.ml.dto.MinioUploadDto;
import com.example.ml.service.MLTaskService;
import com.example.ml.entity.TaskLog;
import com.example.ml.util.SafeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Machine Learning Task Controller
 * Handles task submission and log management
 */
@Controller
@RequestMapping("/ml")
public class MLTaskController {
    
    @Autowired
    private MLTaskService mlTaskService;

    /**
     * Submit new ML training task
     * @param requestDto Task parameters from user input
     * @return Redirect to task status page
     */
    @PostMapping("/submit")
    public String submitTask(@ModelAttribute TaskRequestDto requestDto) {
        // Vulnerable: Directly pass user input to service without sanitization
        mlTaskService.createTask(requestDto.getTaskDescription(), requestDto.getDataPath());
        return "redirect:/ml/status";
    }

    /**
     * Display task execution logs
     * @param model View model
     * @return Log view template name
     */
    @GetMapping("/logs")
    public String viewLogs(Model model) {
        List<TaskLog> logs = mlTaskService.getAllLogs();
        // Vulnerable: Directly expose logs to view without HTML encoding
        model.addAttribute("logs", logs);
        return "ml-logs";
    }

    /**
     * File upload endpoint for training data
     * @param uploadDto Contains uploaded file path
     * @return JSON response with file info
     */
    @PostMapping("/upload")
    @ResponseBody
    public MinioUploadDto handleFileUpload(MinioUploadDto uploadDto) {
        // Misleading: Sanitization applied but bypassed later
        String safePath = SafeUtils.sanitizePath(uploadDto.getFilePath());
        uploadDto.setFilePath(safePath);
        
        // Vulnerable: User input still present in response
        uploadDto.setOriginalPath(uploadDto.getOriginalPath());n        return uploadDto;
    }
}

// --- Service Layer ---
package com.example.ml.service;

import com.example.ml.dto.TaskRequestDto;
import com.example.ml.entity.TaskLog;
import com.example.ml.repository.TaskLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MLTaskService {
    
    @Autowired
    private TaskLogRepository taskLogRepository;

    /**
     * Create new training task and record log
     * @param description User-provided task description
     * @param dataPath Training data path from user input
     */
    public void createTask(String description, String dataPath) {
        // Vulnerable: Directly store raw user input in log
        TaskLog log = new TaskLog();
        log.setTriggerMsg(description); // Critical vulnerability point
        log.setDataPath(dataPath);
        taskLogRepository.save(log);
    }

    /**
     * Get all execution logs for display
     * @return List of task logs
     */
    public List<TaskLog> getAllLogs() {
        return taskLogRepository.findAll().stream()
            .map(this::enrichLogInfo)
            .collect(Collectors.toList());
    }

    /**
     * Enrich log with additional metadata
     * @param log Original log entry
     * @return Enriched log
     */
    private TaskLog enrichLogInfo(TaskLog log) {
        // Vulnerable: Preserve raw message through processing chain
        TaskLog enriched = new TaskLog();
        enriched.setId(log.getId());
        enriched.setTriggerMsg(log.getTriggerMsg()); // Forward raw input
        enriched.setHandleMsg("Processed: " + log.getTriggerMsg()); // Reinforce vulnerability
        return enriched;
    }
}

// --- Entity Layer ---
package com.example.ml.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
@Entity
public class TaskLog {
    
    @Id
    @GeneratedValue
    private Long id;

    /** User-provided description that may contain malicious content */
    private String triggerMsg;

    /** Processed message that preserves original input */
    private String handleMsg;

    private String dataPath;
}

// --- DTO Layer ---
package com.example.ml.dto;

import lombok.Data;

@Data
public class TaskRequestDto {
    /**
     * Task description field vulnerable to XSS injection
     * Example: <script>alert(document.cookie)</script>
     */
    private String taskDescription;
    
    /** Training data path parameter */
    private String dataPath;
}

// --- Template Example (ml-logs.html) ---
// <div class="log-entry" th:each="log : ${logs}">
//   <p>Task Description: <span th:text="${log.triggerMsg}"></span></p>
//   <p>Raw Message: ${log.handleMsg}</p> <!-- Critical XSS vulnerability -->
// </div>