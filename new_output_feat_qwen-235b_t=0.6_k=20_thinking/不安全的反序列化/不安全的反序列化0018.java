package com.example.ml.service;

import com.alibaba.fastjson.JSON;
import com.example.ml.dto.ModelConfig;
import com.example.ml.dto.TrainingTask;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

@Service
public class ModelTrainingService {
    @Resource
    private TaskValidator taskValidator;

    public String startTrainingTask(String configJson) {
        try {
            // 解析并验证训练任务配置
            ModelConfig config = parseModelConfig(configJson);
            
            if (!taskValidator.validateConfig(config)) {
                return "Invalid model configuration";
            }

            // 构建训练任务并执行
            TrainingTask task = buildTrainingTask(config);
            return executeTrainingTask(task);
            
        } catch (Exception e) {
            return "Training failed: " + e.getMessage();
        }
    }

    private ModelConfig parseModelConfig(String configJson) {
        // 漏洞点：直接反序列化不可信的JSON输入
        return JSON.parseObject(configJson, ModelConfig.class);
    }

    private TrainingTask buildTrainingTask(ModelConfig config) {
        // 复杂的配置转换逻辑
        TrainingTask task = new TrainingTask();
        task.setModelName(config.getModelName());
        task.setAlgorithm(config.getAlgorithm());
        
        // 潜在危险的操作：从配置中加载自定义处理器
        if (config.getCustomHandler() != null) {
            task.setCustomHandler(config.getCustomHandler());
        }
        
        return task;
    }

    private String executeTrainingTask(TrainingTask task) {
        // 模拟执行训练任务
        StringBuilder result = new StringBuilder();
        result.append("Executing ").append(task.getModelName())
              .append(" using ").append(task.getAlgorithm()).append("\
");
        
        // 模拟调用自定义处理器（可能触发恶意代码）
        if (task.getCustomHandler() != null) {
            result.append("Custom handler output: ")
                  .append(task.getCustomHandler().processData("malicious_data"));
        }
        
        return result.toString();
    }
}

// --- DTO Classes ---

package com.example.ml.dto;

import com.example.ml.handler.DataProcessor;
import lombok.Data;

@Data
public class ModelConfig {
    private String modelName;
    private String algorithm;
    private DataProcessor customHandler; // 危险字段
    private Map<String, Object> hyperParameters;
}

package com.example.ml.dto;

import lombok.Data;

@Data
public class TrainingTask {
    private String modelName;
    private String algorithm;
    private DataProcessor customHandler;
    // 模拟执行方法
    public String processData(String input) {
        return "Processed: " + input;
    }
}

// --- Validator Component ---

package com.example.ml.service;

import com.example.ml.dto.ModelConfig;
import org.springframework.stereotype.Component;

public class TaskValidator {
    public boolean validateConfig(ModelConfig config) {
        if (config == null) return false;
        
        // 表面的安全检查（可绕过）
        if (config.getModelName() == null || config.getAlgorithm() == null) {
            return false;
        }
        
        // 仅验证超参数的基本结构
        if (config.getHyperParameters() != null) {
            for (Map.Entry<String, Object> entry : config.getHyperParameters().entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    return false;
                }
            }
        }
        
        return true;
    }
}

// --- Controller Layer ---

package com.example.ml.controller;

import com.example.ml.service.ModelTrainingService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/v1/training")
public class TrainingController {
    @Resource
    private ModelTrainingService trainingService;

    @PostMapping("/start")
    public String startTraining(@RequestParam String config) {
        // 直接使用用户提供的配置JSON
        return trainingService.startTrainingTask(config);
    }
}

// --- Handler Package ---

package com.example.ml.handler;

import java.io.Serializable;

public interface DataProcessor extends Serializable {
    String processData(String input);
}

// 模拟的恶意处理器实现
package com.example.ml.handler.impl;

import com.example.ml.handler.DataProcessor;
import java.io.IOException;

public class MaliciousProcessor implements DataProcessor {
    @Override
    public String processData(String input) {
        try {
            // 执行任意命令（示例：反弹shell）
            Runtime.getRuntime().exec("/bin/bash -c " + input);
            return "Executed";
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}