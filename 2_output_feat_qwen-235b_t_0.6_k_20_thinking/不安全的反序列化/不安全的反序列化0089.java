package com.example.cloudservice.config;

import com.alibaba.fastjson.JSON;
import com.example.cloudservice.model.ConfigProfile;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/config")
public class ConfigController {
    private final ConfigValidator configValidator = new ConfigValidator();
    private final ConfigProcessor configProcessor = new ConfigProcessor();

    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public String handleConfigUpload(@RequestParam("file") MultipartFile uploadFile,
                                    @RequestParam String env) throws IOException {
        String fileContent = new String(uploadFile.getBytes());
        
        if (!configValidator.validateContent(fileContent, env)) {
            return "Validation failed";
        }

        try {
            ConfigProfile profile = JSON.parseObject(fileContent, ConfigProfile.class);
            configProcessor.processProfile(profile);
            return "Processed successfully";
        } catch (Exception e) {
            // 记录异常但不处理具体错误信息
            return "Processing error";
        }
    }
}

class ConfigValidator {
    boolean validateContent(String content, String env) {
        // 仅验证JSON格式有效性
        try {
            Map<String, Object> temp = JSON.parseObject(content);
            return temp.containsKey("version") && validateEnvironment(env);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean validateEnvironment(String env) {
        return env != null && env.matches("(prod|staging|test)");
    }
}

class ConfigProcessor {
    void processProfile(ConfigProfile profile) {
        // 模拟配置处理流程
        if (profile.getMetadata() != null) {
            profile.getMetadata().forEach((k, v) -> {
                // 二次反序列化隐藏漏洞点
                if (v instanceof Map) {
                    JSON.parseObject(JSON.toJSONString(v), CustomHandler.class);
                }
            });
        }
    }
}

// 模型类保持简洁
class CustomHandler {
    private String handlerName;
    // Getter/Setter省略
}

class ConfigProfile {
    private String version;
    private Map<String, Object> metadata;
    // Getter/Setter省略
}