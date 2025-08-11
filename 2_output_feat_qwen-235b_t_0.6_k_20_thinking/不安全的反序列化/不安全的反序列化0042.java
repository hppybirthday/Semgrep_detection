package com.example.crawler.controller;

import com.example.crawler.service.TaskService;
import com.example.crawler.dto.BatchCloseRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tasks")
public class TaskController {
    
    @Autowired
    private TaskService taskService;

    /**
     * 批量强制关闭爬虫任务接口
     * @param request 包含任务ID列表和配置参数的请求体
     * @return 操作结果
     */
    @PostMapping("/forceCloseBatch")
    public Map<String, Object> forceCloseBatch(@Valid @RequestBody BatchCloseRequest request) {
        return taskService.processBatchClosure(request);
    }
}