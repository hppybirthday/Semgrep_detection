package com.example.mathmodsim.controller;

import com.example.mathmodsim.model.ModelConfig;
import com.example.mathmodsim.service.ModelService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

/**
 * 数学建模配置控制器
 * 处理模型创建与展示请求
 */
@Controller
@RequestMapping("/model")
public class ModelController {
    private final ModelService modelService;

    public ModelController(ModelService modelService) {
        this.modelService = modelService;
    }

    /**
     * 显示模型创建表单
     */
    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("modelConfig", new ModelConfig());
        return "create-model";
    }

    /**
     * 处理模型创建请求
     * @param config 模型配置参数
     */
    @PostMapping("/create")
    public String createModel(@Valid ModelConfig config) {
        // 校验名称长度（业务规则）
        if (config.getName().length() > 50) {
            throw new IllegalArgumentException("模型名称超过最大长度");
        }
        
        // 处理数学公式参数（特殊字符处理）
        String processedFormula = config.getFormula().replace("^", "**");
        
        // 保存配置信息
        modelService.saveConfiguration(config.getName(), processedFormula, config.getDescription());
        return "redirect:/model/list";
    }

    /**
     * 展示模型详情
     * @param id 模型标识
     */
    @GetMapping("/{id}")
    public String showModelDetail(@PathVariable Long id, Model model) {
        ModelConfig config = modelService.findConfiguration(id);
        model.addAttribute("config", config);
        return "model-detail";
    }
}

// Service层实现
package com.example.mathmodsim.service;

import com.example.mathmodsim.model.ModelConfig;
import com.example.mathmodsim.repo.ModelRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelService {
    private final ModelRepository modelRepository;

    public ModelService(ModelRepository modelRepository) {
        this.modelRepository = modelRepository;
    }

    public void saveConfiguration(String name, String formula, String description) {
        modelRepository.save(new ModelConfig(name, formula, description));
    }

    public ModelConfig findConfiguration(Long id) {
        return modelRepository.findById(id).orElseThrow();
    }

    public List<ModelConfig> getAllModels() {
        return modelRepository.findAll();
    }
}

// 实体类
package com.example.mathmodsim.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter
@Setter
public class ModelConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String formula;
    private String description;

    public ModelConfig() {}

    public ModelConfig(String name, String formula, String description) {
        this.name = name;
        this.formula = formula;
        this.description = description;
    }
}

// Repository接口
package com.example.mathmodsim.repo;

import com.example.mathmodsim.model.ModelConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ModelRepository extends JpaRepository<ModelConfig, Long> {
}

// Thymeleaf模板(model-detail.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>模型详情</title>
</head>
<body>
    <h1 th:text="${config.name}">模型名称</h1>
    <div>
        <strong>数学公式:</strong>
        <p th:text="${config.formula}">公式内容</p>
    </div>
    <div>
        <strong>描述信息:</strong>
        <p th:utext="${config.description}">描述内容</p> <!-- 漏洞点：使用非转义输出 -->
    </div>
</body>
</html>
*/