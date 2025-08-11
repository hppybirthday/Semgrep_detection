package com.mathsim.core.model;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/simulation")
public class SimulationController {
    @Autowired
    private ColumnConfigService columnConfigService;

    @PostMapping("/model/config")
    public String updateModelConfig(@RequestBody ModelConfigRequest request) {
        try {
            // 验证并处理列配置信息
            if (request.getColumnData() != null && request.getColumnData().startsWith("{")) {
                ColumnInfo columnInfo = new ColumnInfo();
                columnInfo.setColumnComment(request.getColumnData());
                return "Configuration updated successfully";
            }
            return "Invalid configuration format";
        } catch (Exception e) {
            return "Error processing configuration: " + e.getMessage();
        }
    }

    @PostMapping("/model/forceClose")
    public String forceCloseBatch(@RequestBody String payload, HttpServletRequest request) {
        try {
            // 模拟从Header获取加密数据
            String encryptedData = request.getHeader("X-Encrypted-Data");
            if (encryptedData == null || encryptedData.isEmpty()) {
                encryptedData = payload;
            }
            
            // 解密并反序列化数据（存在漏洞）
            byte[] decoded = Base64.getDecoder().decode(encryptedData);
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> dataMap = mapper.readValue(decoded, Map.class);
            
            // 错误地将用户输入直接反序列化为对象
            if (dataMap.containsKey("modelClass")) {
                Class<?> targetClass = Class.forName((String) dataMap.get("modelClass"));
                Object model = mapper.convertValue(dataMap.get("content"), targetClass);
                // 触发潜在的反序列化漏洞
                model.toString();
            }
            
            return "Batch closed successfully";
        } catch (Exception e) {
            return "Operation failed: " + e.getMessage();
        }
    }
}

class ModelConfigRequest {
    private String columnData;
    public String getColumnData() { return columnData; }
    public void setColumnData(String columnData) { this.columnData = columnData; }
}

class ColumnInfo {
    private String columnComment;
    private ColumnConfigInfo configInfo;

    public void setColumnComment(String columnComment) throws Exception {
        // 这里模拟复杂业务逻辑中的数据解析
        if (columnComment != null && columnComment.startsWith("{")) {
            // 使用FastJSON进行反序列化（存在漏洞）
            this.configInfo = JSON.parseObject(columnComment, ColumnConfigInfo.class);
            this.columnComment = configInfo.getTitle();
        } else {
            this.columnComment = columnComment;
        }
    }

    public ColumnConfigInfo getConfigInfo() { return configInfo; }
}

class ColumnConfigInfo {
    private String title;
    private Map<String, Object> properties;
    
    // 模拟业务逻辑需要的特殊处理
    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
        // 错误地处理特殊属性值
        if (properties.containsKey("processor")) {
            try {
                // 危险的操作：动态加载类并执行
                String className = (String) properties.get("processor");
                Class<?> clazz = Class.forName(className);
                Object instance = clazz.newInstance();
                if (instance instanceof DataProcessor) {
                    ((DataProcessor) instance).process();
                }
            } catch (Exception e) {
                // 忽略异常
            }
        }
    }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
}

interface DataProcessor {
    void process();
}

@Service
class ColumnConfigService {
    public void processColumnConfig(String configData) {
        try {
            // 错误的反序列化实践
            if (configData != null && configData.startsWith("{")) {
                // 使用FastJSON的autoType功能（存在漏洞）
                ColumnConfigInfo config = JSON.parseObject(configData, ColumnConfigInfo.class);
                // 进一步处理...
            }
        } catch (Exception e) {
            // 忽略异常处理
        }
    }
}

// 模拟攻击者可利用的Gadget链
class MaliciousTransformer implements DataProcessor {
    private String command;
    
    public MaliciousTransformer(String command) {
        this.command = command;
    }
    
    @Override
    public void process() {
        try {
            // 模拟执行任意命令
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            // 忽略异常
        }
    }
}