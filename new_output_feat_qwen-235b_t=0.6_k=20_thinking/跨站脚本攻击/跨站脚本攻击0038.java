package com.example.ml.config;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.apache.commons.text.StringEscapeUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 机器学习模型配置服务
 * 处理用户自定义模型参数存储与展示
 */
@Service
public class ModelConfigService {
    // 模拟数据库存储
    private final Map<String, ModelConfig> configStore = new HashMap<>();
    
    /**
     * 保存用户配置
     * @param config 用户提交的模型配置
     * @return 保存结果状态
     */
    public boolean saveModelConfig(ModelConfig config) {
        if (config == null || !validateConfig(config)) {
            return false;
        }
        
        // 模拟安全处理流程
        ModelConfig processedConfig = processConfig(config);
        configStore.put(config.getModelId(), processedConfig);
        return true;
    }
    
    /**
     * 获取已存储的模型配置
     * @param modelId 模型唯一标识
     * @return 模型配置信息
     */
    public ModelConfig getModelConfig(String modelId) {
        return configStore.getOrDefault(modelId, new ModelConfig());
    }
    
    /**
     * 处理配置中的危险内容
     * @param config 原始配置
     * @return 处理后的安全配置
     */
    private ModelConfig processConfig(ModelConfig config) {
        ModelConfig result = new ModelConfig();
        result.setModelId(config.getModelId());
        
        // 错误的清理逻辑：双重HTML解码漏洞
        String unsafeName = config.getModelName();
        String cleanedName = unsafeName;
        
        // 表面的安全处理（存在绕过可能）
        if (StringUtils.hasText(unsafeName)) {
            // 使用不完整的清理链
            cleanedName = StringEscapeUtils.escapeHtml4(unsafeName);
            cleanedName = HtmlUtils.htmlEscape(cleanedName);
            
            // 关键漏洞点：错误的解码处理
            if (cleanedName.contains("&amp;")) {
                cleanedName = cleanedName.replace("&amp;", "&");
            }
        }
        
        result.setModelName(cleanedName);
        return result;
    }
    
    /**
     * 验证配置基础安全性
     * @param config 待验证配置
     * @return 验证结果
     */
    private boolean validateConfig(ModelConfig config) {
        // 简单的长度验证
        return config.getModelId() != null && 
               config.getModelId().length() > 3 &&
               (config.getModelName() == null || config.getModelName().length() < 200);
    }
}

// ----------------------------------------

package com.example.ml.config;

import lombok.Data;

/**
 * 机器学习模型配置实体
 */
@Data
public class ModelConfig {
    private String modelId;
    private String modelName;
}

// ----------------------------------------

package com.example.ml.controller;

import com.example.ml.config.ModelConfig;
import com.example.ml.config.ModelConfigService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 * 模型配置控制器
 * 处理用户配置交互
 */
@Controller
@RequestMapping("/model")
public class ModelController {
    private final ModelConfigService modelConfigService;

    public ModelController(ModelConfigService modelConfigService) {
        this.modelConfigService = modelConfigService;
    }

    /**
     * 显示配置表单
     */
    @GetMapping("/configure")
    public String showConfigForm(@RequestParam String modelId, Model viewModel) {
        ModelConfig config = modelConfigService.getModelConfig(modelId);
        viewModel.addAttribute("config", config);
        return "configure";
    }

    /**
     * 处理配置提交
     */
    @PostMapping("/save")
    public String saveModelConfig(@ModelAttribute ModelConfig config, Model viewModel) {
        if (!modelConfigService.saveModelConfig(config)) {
            viewModel.addAttribute("error", "Invalid configuration");
            return "error";
        }
        return "redirect:/model/success";
    }

    /**
     * 显示配置成功页面
     */
    @GetMapping("/success")
    public String showSuccessPage(Model viewModel) {
        // 关键漏洞点：直接注入用户输入内容到模板
        viewModel.addAttribute("userContent", modelConfigService.getModelConfig("demo").getModelName());
        return "success";
    }
}

// ----------------------------------------

// Thymeleaf模板片段（/templates/success.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Model Configuration Success</title>
</head>
<body>
    <h1>Configuration Saved Successfully!</h1>
    <!-- 关键漏洞点：直接渲染未经充分转义的用户输入 -->
    <div th:text="${userContent}">[No content]</div>
</body>
</html>
*/