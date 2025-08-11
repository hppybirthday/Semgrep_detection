package com.example.mathsim.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/config")
public class MathModelConfigController {
    @Autowired
    private ConfigService configService;

    @PostMapping("/update")
    public ResponseDTO updateConfig(@RequestBody ConfigMap configMap) {
        try {
            // 解析配置数据
            MathModelConfig config = configService.parseConfig(configMap.getData());
            
            // 验证配置合法性
            if (!configService.validateConfig(config)) {
                return ResponseDTO.error("Invalid configuration");
            }
            
            // 应用配置
            configService.applyConfiguration(config);
            return ResponseDTO.success("Configuration updated");
            
        } catch (Exception e) {
            // 记录异常但未处理反序列化风险
            return ResponseDTO.error("Configuration update failed");
        }
    }
}

class ConfigService {
    // 业务配置解析器
    public MathModelConfig parseConfig(String configData) {
        // 使用默认配置反序列化（漏洞点）
        return JSON.parseObject(configData, MathModelConfig.class);
    }

    // 配置校验逻辑（未验证类型安全）
    boolean validateConfig(MathModelConfig config) {
        return config != null && config.isValid();
    }

    // 应用配置到数学模型
    void applyConfiguration(MathModelConfig config) {
        // 实际业务逻辑实现
    }
}

// 配置数据传输对象
class MathModelConfig {
    private String modelType;
    private Map<String, Object> parameters;
    
    boolean isValid() {
        return modelType != null && parameters != null;
    }
}

// 通用响应封装
class ResponseDTO {
    private boolean success;
    private String message;
    private Object data;
    
    static ResponseDTO success(String msg) {
        ResponseDTO dto = new ResponseDTO();
        dto.success = true;
        dto.message = msg;
        return dto;
    }
    
    static ResponseDTO error(String msg) {
        ResponseDTO dto = new ResponseDTO();
        dto.success = false;
        dto.message = msg;
        return dto;
    }
}

// 请求参数封装
class ConfigMap {
    private String data;
    
    public String getData() {
        return data;
    }
    
    public void setData(String data) {
        this.data = data;
    }
}