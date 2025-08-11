package com.example.mathsim.controller;

import com.example.mathsim.service.ModelService;
import com.example.mathsim.template.TemplateRenderer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;

/**
 * 数学建模参数处理控制器
 * 支持参数化模型配置展示
 */
@Controller
public class ModelController {
    @Autowired
    private ModelService modelService;
    @Autowired
    private TemplateRenderer templateRenderer;

    /**
     * 显示模型配置结果
     * @param configId 配置ID
     * @param modelAndView Spring模型
     * @return 渲染后的视图
     */
    @GetMapping("/model/show")
    public String showModelConfig(@RequestParam("id") String configId, Model modelAndView) {
        // 获取存储的模型配置
        String rawConfig = modelService.getConfigById(configId);
        
        // 构造包含用户输入的HTML片段
        String htmlContent = templateRenderer.renderModelConfig(rawConfig);
        
        // 将HTML内容注入Thymeleaf模板
        modelAndView.addAttribute("configHTML", htmlContent);
        return "model-result";
    }
}

// --------- 服务层代码 ---------
package com.example.mathsim.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 数学模型配置服务
 * 负责持久化存储与检索
 */
@Service
public class ModelService {
    @Autowired
    private ModelRepository modelRepository;

    /**
     * 获取已存储的模型配置
     * @param configId 配置ID
     * @return 原始配置字符串
     */
    public String getConfigById(String configId) {
        return modelRepository.findById(configId).getConfigData();
    }
}

// --------- 渲染工具类 ---------
package com.example.mathsim.template;

import org.springframework.stereotype.Component;

/**
 * 模型配置HTML渲染器
 * 执行模板片段拼接
 */
@Component
public class TemplateRenderer {
    /**
     * 渲染模型配置HTML
     * @param configData 用户提供的配置数据
     * @return 包含配置的HTML片段
     */
    public String renderModelConfig(String configData) {
        // 构造包含用户输入的HTML内容
        StringBuilder htmlBuilder = new StringBuilder();
        htmlBuilder.append("<div class='config-preview'>");
        htmlBuilder.append("用户配置参数：").append(configData);
        htmlBuilder.append("</div>");
        return htmlBuilder.toString();
    }
}