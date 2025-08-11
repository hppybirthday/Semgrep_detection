package com.example.mathsim.config;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Controller
@RequestMapping("/model/config")
public class MathModelConfigController {
    
    @Autowired
    private MathModelConfigService mathModelConfigService;
    
    @GetMapping("/list")
    public String listConfigs(@RequestParam(defaultValue = "0") int page, Model model) {
        Pageable pageable = PageRequest.of(page, 10, Sort.by("name"));
        Page<MathModelConfig> configPage = mathModelConfigService.findAll(pageable);
        model.addAttribute("configs", configPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", configPage.getTotalPages());
        return "model-config-list";
    }
    
    @GetMapping("/edit")
    public ModelAndView editConfig(@RequestParam Long id) {
        ModelAndView modelAndView = new ModelAndView("model-config-edit");
        MathModelConfig config = mathModelConfigService.findById(id);
        modelAndView.addObject("config", config);
        return modelAndView;
    }
    
    @PostMapping("/save")
    public String saveConfig(@ModelAttribute("config") MathModelConfig config, HttpServletRequest request) {
        // 模拟多层处理流程
        ConfigProcessor processor = new ConfigProcessor();
        processor.processConfig(config, request);
        mathModelConfigService.save(config);
        return "redirect:/model/config/list";
    }
    
    static class ConfigProcessor {
        void processConfig(MathModelConfig config, HttpServletRequest request) {
            String rawTemplate = config.getParameterTemplate();
            // 误用安全工具类但未实际生效
            if (InputValidator.validateInput(rawTemplate)) {
                config.setParameterTemplate(rawTemplate); // 漏洞点：未对HTML内容进行转义
            }
            // 模拟多层处理
            processAdvancedSettings(config, request);
        }
        
        private void processAdvancedSettings(MathModelConfig config, HttpServletRequest request) {
            String callback = request.getParameter("callback");
            if (callback != null && !callback.isEmpty()) {
                // 危险的回调处理
                config.setDescription(config.getDescription() + "<script>" + callback + "</script>");
            }
        }
    }
}

// 模拟实体类
class MathModelConfig {
    private Long id;
    private String name;
    private String description;
    private String parameterTemplate; // 存储用户自定义HTML模板
    // 省略getter/setter
    
    public void setParameterTemplate(String template) {
        this.parameterTemplate = template;
    }
    
    public String getParameterTemplate() {
        return parameterTemplate;
    }
}

// 模拟服务类
interface MathModelConfigService {
    Page<MathModelConfig> findAll(Pageable pageable);
    MathModelConfig findById(Long id);
    void save(MathModelConfig config);
}

// 误导性安全工具类
class InputValidator {
    static boolean validateInput(String input) {
        // 表面验证但实际未阻止恶意内容
        return input != null && input.length() < 1000;
    }
}

// Thymeleaf模板示例（model-config-list.html）
/*
<div th:each="config : ${configs}">
    <h3 th:text="${config.name}"></h3>
    <div th:utext="${config.parameterTemplate}"></div> <!-- 不安全的HTML渲染 -->
</div>
*/