package com.bigdata.process.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/job")
public class DataProcessController {
    private final MessageService messageService = new MessageService();

    @GetMapping("/execute")
    public ResponseEntity<?> executeJob(@RequestParam String data) {
        try {
            if (data.contains("ERROR")) {
                throw new JobExecutionException("Invalid data format: " + data);
            }
            // 处理大数据作业逻辑
            return ResponseEntity.ok().build();
        } catch (JobExecutionException e) {
            return new ResponseEntity<>(
                Map.of("error", "Job failed: " + e.getMessage()),
                HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }

    @ExceptionHandler(JobExecutionException.class)
    public ResponseEntity<?> handleJobExceptions(JobExecutionException ex, WebRequest request) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("message", messageService.formatErrorMessage(ex.getMessage()));
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

class JobExecutionException extends RuntimeException {
    public JobExecutionException(String message) {
        super(message);
    }
}

class MessageService {
    String formatErrorMessage(String rawMsg) {
        // 格式化错误消息（业务规则）
        return "Error occurred: " + rawMsg;
    }
}