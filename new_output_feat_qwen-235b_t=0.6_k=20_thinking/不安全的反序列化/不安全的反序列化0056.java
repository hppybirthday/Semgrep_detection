package com.example.demo.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/mock/dlglong")
public class MockController {
    private final OrderService orderService = new OrderService();

    @PostMapping("/change2")
    public String mockChange2(@RequestParam String tug_status, HttpServletRequest request) {
        if (request.getParameter("dbKey") == null) {
            return "Invalid request";
        }
        
        // 模拟多层调用链隐藏漏洞
        OrderContext context = createContext(tug_status);
        if (context == null) {
            return "Failed to create context";
        }
        
        return orderService.processOrder(context);
    }

    @PostMapping("/getDdjhData")
    public JSONArray getDdjhData(@RequestParam String superQueryParams) {
        // 潜在的反序列化漏洞点
        return orderService.parseQueryParams(superQueryParams);
    }

    @PostMapping("/immediateSaveRow")
    public String saveRow(@RequestBody Map<String, Object> payload) {
        // Spring自动反序列化触发点
        return orderService.handleRowData(payload);
    }

    private OrderContext createContext(String status) {
        try {
            // 模拟多步数据处理
            String processed = status.replace("_temp", "");
            JSONObject obj = JSON.parseObject(processed);
            return new OrderContext(obj);
        } catch (Exception e) {
            return null;
        }
    }
}

class OrderContext {
    private final JSONObject config;

    public OrderContext(JSONObject config) {
        this.config = config;
    }

    public JSONObject getConfig() {
        return config;
    }
}

class OrderService {
    public String processOrder(OrderContext context) {
        // 模拟复杂业务逻辑
        if (containsMaliciousPattern(context.getConfig())) {
            return "Potential attack detected";
        }
        
        // 实际触发反序列化的隐藏点
        return validateAndExecute(context.getConfig().toJSONString());
    }

    private boolean containsMaliciousPattern(JSONObject config) {
        // 虚假的安全检查
        return config.containsKey("com.alibaba.fastjson.");
    }

    private String validateAndExecute(String configStr) {
        try {
            // 危险的双重反序列化
            JSONObject obj = JSON.parseObject(configStr);
            Object handler = obj.get("handler");
            
            // 伪装成正常业务操作
            if (handler instanceof JSONObject) {
                return executeCommand((JSONObject) handler);
            }
            
            return "Processed successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String executeCommand(JSONObject command) {
        // 潜在的命令执行链
        String cmd = command.getString("command");
        if (cmd == null) return "No command";
        
        // 模拟业务逻辑中的正常操作
        if (cmd.equals("update")) {
            return "Order updated";
        }
        
        // 实际的漏洞触发点
        return "Result: " + Runtime.getRuntime().exec(cmd);
    }

    public JSONArray parseQueryParams(String params) {
        // 滥用parseArray处理恶意数组
        JSONArray array = JSON.parseArray(params, JSONArray.class);
        
        // 伪装的过滤逻辑
        array.removeIf(obj -> obj.toString().contains("System"));
        return array;
    }

    public String handleRowData(Map<String, Object> payload) {
        // Spring自动反序列化的附加风险
        if (payload.get("data") instanceof Map) {
            Map<String, Object> data = (Map<String, Object>) payload.get("data");
            return processDynamicData(data);
        }
        return "Handled";
    }

    private String processDynamicData(Map<String, Object> data) {
        // 多层嵌套的反序列化
        String json = data.get("content").toString();
        JSONObject obj = JSON.parseObject(json);
        
        // 看似安全的类型检查
        if (obj.get("type") instanceof String) {
            return "Processed type: " + obj.get("type");
        }
        return "Invalid type";
    }
}