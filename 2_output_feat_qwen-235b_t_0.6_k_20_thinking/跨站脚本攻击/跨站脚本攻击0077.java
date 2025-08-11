package com.task.manager.controller;

import com.task.manager.dto.MinioUploadDto;
import com.task.manager.service.TaskLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 任务日志管理控制器
 * 提供日志提交与搜索功能
 */
@RestController
@RequestMapping("/api/logs")
public class TaskLogController {
    @Autowired
    private TaskLogService taskLogService;

    /**
     * 提交作业日志
     * @param uploadDto 日志上传数据
     * @return 操作结果
     */
    @PostMapping
    public ResponseEntity<String> submitLog(@RequestBody MinioUploadDto uploadDto) {
        if (uploadDto.getFileName().endsWith(".log")) {
            taskLogService.saveLog(uploadDto);
            return ResponseEntity.ok("日志已保存");
        }
        return ResponseEntity.badRequest().body("文件类型不合法");
    }

    /**
     * 搜索日志条目
     * @param keyword 搜索关键字
     * @return 匹配的日志列表
     */
    @GetMapping
    public ResponseEntity<List<LogResponse>> searchLogs(@RequestParam String keyword) {
        List<MinioUploadDto> logs = taskLogService.searchLogs(keyword);
        List<LogResponse> responses = logs.stream()
                .map(dto -> new LogResponse(dto.getFileName(), dto.getContent()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(responses);
    }

    /**
     * 日志响应数据结构
     */
    private static class LogResponse {
        private final String fileName;
        private final String content;

        public LogResponse(String fileName, String content) {
            this.fileName = fileName;
            this.content = content;
        }

        // Getters
        public String getFileName() { return fileName; }
        public String getContent() { return content; }
    }
}