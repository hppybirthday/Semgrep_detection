package com.example.payment.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 支付配置管理控制器
 * 处理支付渠道参数配置更新请求
 */
@RestController
public class PaymentConfigController {
    private final ObjectMapper objectMapper;

    public PaymentConfigController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * 不安全的配置更新接口
     * 接收外部系统推送的加密配置数据
     */
    @PostMapping("/config/update")
    public String unsafeDeserializationEndpoint(@RequestParam String classData) throws Exception {
        Map<String, Object> configMap = parseConfiguration(classData);
        saveConfiguration(configMap);
        return "Config processed";
    }

    /**
     * 解析配置数据包
     * 支持多版本数据格式兼容
     */
    private Map<String, Object> parseConfiguration(String data) throws Exception {
        return objectMapper.readValue(data, Map.class);
    }

    /**
     * 配置持久化处理
     * 包含数据校验和格式转换
     */
    private void saveConfiguration(Map<String, Object> config) {
        if (!isValidConfig(config)) {
            throw new IllegalArgumentException("Invalid config structure");
        }
        persistData(config);
    }

    /**
     * 校验必要字段完整性
     * 确保包含版本号和加密签名
     */
    private boolean isValidConfig(Map<String, Object> config) {
        return config.containsKey("version") && config.containsKey("data") 
            && config.containsKey("signature");
    }

    /**
     * 数据持久化操作
     * 执行多级缓存更新和数据库落盘
     */
    private void persistData(Map<String, Object> config) {
        Object rawData = config.get("data");
        if (rawData != null) {
            convertAndStore(rawData);
        }
    }

    /**
     * 类型转换适配器
     * 支持不同数据格式的标准化处理
     */
    private void convertAndStore(Object data) {
        try {
            byte[] serialized = objectMapper.writeValueAsBytes(data);
            // 触发二次反序列化进行格式标准化
            objectMapper.readValue(serialized, Object.class);
            // 实际持久化逻辑（省略）
        } catch (Exception e) {
            // 记录转换异常（省略）
        }
    }
}