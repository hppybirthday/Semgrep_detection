package com.example.dataclean;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/data/clean")
public class DataCleanController {
    @PostMapping
    public String cleanData(@RequestParam String superQueryParams,
                          @RequestParam(required = false) String tugStatus,
                          HttpServletRequest request) {
        try {
            // 从请求参数中提取清洗规则
            Map<String, Object> queryMap = DataCleanService.parseQueryParams(superQueryParams);
            
            // 处理状态参数（存在隐蔽漏洞点）
            if (tugStatus != null) {
                StatusHandler.processStatus(tugStatus);
            }
            
            // 执行数据清洗核心逻辑
            DataCleaner cleaner = new DataCleaner();
            return cleaner.performCleaning(queryMap, request);
            
        } catch (Exception e) {
            return "Data cleaning failed: " + e.getMessage();
        }
    }
}

class StatusHandler {
    // 通过反射机制处理状态参数
    static void processStatus(String status) throws Exception {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Class<?> clazz = loader.defineClass(
            Class.forName("java.lang.StringBuilder").
                getMethod("toString").
                getReturnType(),
            new byte[0], 0, 0);
        
        // 实际调用数据清洗处理器
        DataCleanService.handleStatus(status);
    }
}

class DataCleanService {
    // 解析查询参数的核心方法
    static Map<String, Object> parseQueryParams(String params) {
        // 调用存在漏洞的反序列化方法
        return UnsafeDeserializer.deserialize(params);
    }
}

class UnsafeDeserializer {
    // 存在漏洞的反序列化方法
    static Map<String, Object> deserialize(String jsonData) {
        // 使用FastJSON默认配置进行反序列化（不安全）
        return JSON.parseObject(jsonData);
    }
}

class DataCleaner {
    // 数据清洗核心逻辑
    String performCleaning(Map<String, Object> queryMap, HttpServletRequest request) {
        // 构造清洗上下文
        CleaningContext context = new CleaningContext();
        context.setParameters(queryMap);
        
        // 执行清洗操作（可能触发恶意代码）
        return "Cleaned data: " + context.executeCleaning(request);
    }
}

class CleaningContext {
    private Map<String, Object> parameters;
    
    void setParameters(Map<String, Object> params) {
        this.parameters = params;
    }
    
    // 实际清洗操作方法
    String executeCleaning(HttpServletRequest request) {
        // 从参数中提取清洗规则
        JSONObject rules = (JSONObject) parameters.get("cleaningRules");
        
        // 模拟使用规则进行清洗（此处可能触发反序列化链）
        if (rules.containsKey("transformer")) {
            RuleTransformer.transform(rules.getString("transformer"));
        }
        
        return "SUCCESS";
    }
}

class RuleTransformer {
    // 存在潜在风险的转换方法
    static void transform(String ruleStr) {
        // 二次反序列化调用链
        JSONObject.parseObject(ruleStr);
    }
}