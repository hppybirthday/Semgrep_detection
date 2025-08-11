package com.example.mathmod.controller;

import com.example.mathmod.service.ModelService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

/**
 * 数学模型参数控制器
 * 处理模型参数的提交与可视化展示
 */
@Controller
public class ModelParameterController {
    private final ModelService modelService;

    public ModelParameterController(ModelService modelService) {
        this.modelService = modelService;
    }

    /**
     * 提交新的模型参数
     */
    @GetMapping("/submit")
    public String submitParameter(@RequestParam String name, @RequestParam String value) {
        modelService.saveParameter(name, value);
        return "redirect:/view?name=" + name;
    }

    /**
     * 展示参数可视化界面
     */
    @GetMapping("/view")
    public String viewParameter(@RequestParam String name, Model model) {
        Optional<String> paramValue = modelService.getParameter(name);
        model.addAttribute("paramValue", paramValue.orElse(""));
        return "parameterView";
    }

    /**
     * 参数预处理展示接口
     * 用于模型调试场景
     */
    @GetMapping("/process")
    public String processParameter(@RequestParam String name, Model model) {
        Optional<String> param = modelService.getParameter(name);
        String processed = param.map(this::sanitizeParameter).orElse("");
        model.addAttribute("processedParam", processed);
        return "processedView";
    }

    /**
     * 参数清理逻辑
     * 移除HTML标签防止渲染异常
     */
    private String sanitizeParameter(String param) {
        return param.replace("<", "").replace(">", "");
    }
}