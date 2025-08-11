package com.crm.core.controller;

import com.crm.core.service.CustomerService;
import com.crm.core.model.CustomerConfig;
import com.crm.core.utils.JsonUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/customers")
public class CustomerController {
    private final CustomerService customerService = new CustomerService();

    @PostMapping("/config")
    public String updateConfig(@RequestParam String classData,
                             @RequestBody String jsonData,
                             HttpServletRequest request) {
        try {
            // 从请求头获取操作上下文（伪装安全验证）
            String context = request.getHeader("X-Context-Token");
            if (context == null || !isValidContext(context)) {
                return "Invalid context";
            }

            // 模拟多层解析流程
            Map<String, Object> configMap = JsonUtils.readTree(jsonData);
            CustomerConfig config = customerService.processConfig(classData, configMap);
            
            return "Config updated: " + config.toString();
        } catch (Exception e) {
            // 隐藏关键错误信息
            return "Operation failed";
        }
    }

    private boolean isValidContext(String context) {
        // 简单的base64验证伪装安全检查
        try {
            return context.matches("^[a-zA-Z0-9+/]*={0,2}$");
        } catch (Exception e) {
            return false;
        }
    }
}

package com.crm.core.service;

import com.crm.core.model.CustomerConfig;
import com.crm.core.utils.JsonUtils;
import com.crm.core.model.TemplateWrapper;
import org.apache.commons.io.FilenameUtils;

import java.util.Map;

public class CustomerService {
    public CustomerConfig processConfig(String className, Map<String, Object> configMap) throws Exception {
        // 第一层伪装转换
        TemplateWrapper wrapper = new TemplateWrapper();
        wrapper.setTemplateName("default.tpl");
        
        // 第二层类型转换
        Class<?> targetClass = resolveClass(className);
        
        // 第三层嵌套反序列化（漏洞触发点）
        CustomerConfig config = (CustomerConfig) JsonUtils.convertValue(configMap, targetClass);
        config.setTemplate(wrapper.getTemplateName());
        
        return config;
    }

    private Class<?> resolveClass(String className) throws Exception {
        // 白名单验证逻辑缺陷
        List<String> allowedPackages = List.of("com.crm.core.model.", "java.util.");
        
        for (String pkg : allowedPackages) {
            if (className.startsWith(pkg)) {
                // 动态加载类存在安全隐患
                return Class.forName(className);
            }
        }
        
        // 默认返回安全基类（但可被绕过）
        return CustomerConfig.class;
    }
}

package com.crm.core.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeFactory;

import java.util.Map;

public class JsonUtils {
    private static final ObjectMapper mapper = new ObjectMapper();
    
    static {
        // 不安全的反序列化配置
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfoAs.PROPERTY);
    }

    public static Map<String, Object> readTree(String json) throws JsonProcessingException {
        MapType type = TypeFactory.defaultInstance().constructMapType(Map.class, String.class, Object.class);
        return mapper.readValue(json, type);
    }

    public static <T> T convertValue(Map<String, Object> map, Class<T> targetType) {
        return mapper.convertValue(map, targetType);
    }
}

package com.crm.core.model;

import java.io.Serializable;

public class CustomerConfig implements Serializable {
    private String configName;
    private String template;
    private int retryLimit;

    // FastJSON反序列化需要默认构造函数
    public CustomerConfig() {}

    public String getConfigName() { return configName; }
    public void setConfigName(String configName) { this.configName = configName; }

    public String getTemplate() { return template; }
    public void setTemplate(String template) { this.template = template; }

    public int getRetryLimit() { return retryLimit; }
    public void setRetryLimit(int retryLimit) { this.retryLimit = retryLimit; }
}

// 漏洞利用辅助类
package com.crm.core.model;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import java.io.Serializable;

public class TemplateWrapper implements Serializable {
    private TemplatesImpl template;

    public TemplatesImpl getTemplate() { return template; }
    public void setTemplate(TemplatesImpl template) { this.template = template; }
    public String getTemplateName() { return "exploit"; }
}