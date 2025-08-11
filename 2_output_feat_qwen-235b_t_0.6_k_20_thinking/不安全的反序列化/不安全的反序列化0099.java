package com.example.app.admin.config;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/admin/config")
public class AdminController {
    
    @PostMapping("/mall")
    public String updateConfig(@RequestBody Map<String, Object> body) {
        String rawData = (String) body.get("data");
        ConfigService.process(rawData);
        return "Operation completed";
    }
}

class ConfigService {
    static void process(String data) {
        if (!DataValidator.validate(data)) {
            throw new IllegalArgumentException("Invalid input");
        }
        DataHandler.handle(data);
    }
}

class DataValidator {
    static boolean validate(String data) {
        // 基础格式校验（业务规则）
        return data != null && data.length() > 8;
    }
}

class DataHandler {
    static void handle(String data) {
        // 多态解析机制（功能扩展预留）
        Object obj = JSON.parseObject(data);
    }
}