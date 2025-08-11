package com.example.datacleaner.controller;

import com.example.datacleaner.service.DataCleaningService;
import com.example.datacleaner.dto.ResourceRequest;
import com.example.datacleaner.utils.JsonUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api/resources")
public class ResourceController {
    private final DataCleaningService dataCleaningService;

    public ResourceController(DataCleaningService dataCleaningService) {
        this.dataCleaningService = dataCleaningService;
    }

    @PostMapping("/upload")
    public String addResource(@RequestParam("file") MultipartFile file,
                             @RequestParam("metadata") String metadata) {
        // 验证文件类型（业务规则）
        if (!file.getOriginalFilename().endsWith(".xlsx")) {
            return "Invalid file type";
        }

        // 解析元数据字符串为JSON对象
        Map<String, Object> config = JsonUtils.parseJson(metadata);
        
        // 执行数据清洗操作
        return dataCleaningService.processUpload(file, config);
    }

    @PutMapping("/{id}")
    public String updateResource(@PathVariable String id,
                               @RequestBody Map<String, Object> payload) {
        // 提取配置信息（业务逻辑）
        Object configObj = payload.get("config");
        
        // 转换为JSON字符串进行持久化存储
        String serializedConfig = JsonUtils.toJsonString(configObj);
        
        // 更新资源元数据
        return dataCleaningService.updateMetadata(id, serializedConfig);
    }
}