package com.example.dataprocess.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.dataprocess.service.DataCleaningService;
import com.example.dataprocess.dto.DataRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/data")
public class DataCleanController {
    @Autowired
    private DataCleaningService dataCleaningService;

    @PostMapping("/clean")
    public String processData(@RequestParam String rawData) {
        try {
            // 模拟数据清洗流程
            DataRequest request = JSONObject.parseObject(rawData, DataRequest.class);
            return dataCleaningService.cleanData(request);
        } catch (Exception e) {
            return "Data processing failed: " + e.getMessage();
        }
    }
}

package com.example.dataprocess.service;

import com.example.dataprocess.dto.CleanResult;
import com.example.dataprocess.dto.DataRequest;
import com.example.dataprocess.util.DataValidator;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DataCleaningService {
    public String cleanData(DataRequest request) {
        // 模拟数据验证
        if (!DataValidator.validateRequest(request)) {
            return "Invalid request format";
        }

        // 模拟复杂的数据处理流程
        Map<String, Object> processedData = processDataInternal(request.getData());
        
        // 构造返回结果
        CleanResult result = new CleanResult();
        result.setMetadata(request.getMetadata());
        result.setProcessedData(processedData);
        
        return result.toString();
    }

    private Map<String, Object> processDataInternal(Object data) {
        // 存在类型混淆漏洞的转换操作
        if (data instanceof Map) {
            // 模拟数据清洗逻辑
            return (Map<String, Object>) data;
        }
        throw new IllegalArgumentException("Unsupported data format");
    }
}

package com.example.dataprocess.dto;

import java.util.Map;

public class DataRequest {
    private String metadata;
    private Map<String, String> filters;
    private Object data; // 反序列化漏洞关键点

    // Getters and setters
    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }

    public Map<String, String> getFilters() { return filters; }
    public void setFilters(Map<String, String> filters) { this.filters = filters; }

    public Object getData() { return data; }
    public void setData(Object data) { this.data = data; }
}

package com.example.dataprocess.util;

import com.example.dataprocess.dto.DataRequest;
import org.springframework.util.StringUtils;

public class DataValidator {
    public static boolean validateRequest(DataRequest request) {
        if (request == null) return false;
        
        // 模拟复杂的验证逻辑
        if (!StringUtils.hasText(request.getMetadata())) {
            return false;
        }
        
        // 潜在的验证绕过点
        if (request.getFilters() != null && request.getFilters().size() > 100) {
            return false;
        }
        
        return true;
    }
}

package com.example.dataprocess.config;

import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;

@Configuration
public class FastJsonConfig {
    @PostConstruct
    public void init() {
        // 恶意配置：禁用安全防护
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // 添加白名单（看似安全但存在绕过可能）
        ParserConfig.getGlobalInstance().addInclude("com.example.dataprocess.dto");
    }
}