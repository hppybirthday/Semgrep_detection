package com.example.mathsim.controller;

import com.example.mathsim.model.MathModel;
import com.example.mathsim.service.ModelService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

/**
 * 数学建模应用控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/models")
public class ModelController {
    @Resource
    private ModelService modelService;

    /**
     * 显示模型创建表单
     */
    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("mathModel", new MathModel());
        return "create_model";
    }

    /**
     * 处理模型创建请求
     */
    @PostMapping("/create")
    public String createModel(@ModelAttribute("mathModel") MathModel mathModel) {
        // 漏洞点：直接保存未经净化的用户输入
        modelService.saveModel(mathModel);
        return "redirect:/models/list";
    }

    /**
     * 展示模型列表
     */
    @GetMapping("/list")
    public String listModels(Model model) {
        List<MathModel> models = modelService.getAllModels();
        // 将模型列表传递给视图
        model.addAttribute("models", models);
        return "model_list";
    }
}

// --- 服务层代码 ---
package com.example.mathsim.service;

import com.example.mathsim.model.MathModel;
import com.example.mathsim.repository.ModelRepository;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;

@Service
public class ModelService {
    @Resource
    private ModelRepository modelRepository;

    /**
     * 保存模型数据（包含潜在恶意输入）
     */
    public void saveModel(MathModel model) {
        // 模拟业务处理逻辑
        if (model.getName() == null || model.getName().isEmpty()) {
            model.setName("Untitled_Model");
        }
        
        // 漏洞点：未对用户输入进行HTML编码
        modelRepository.save(model);
    }

    /**
     * 获取所有模型数据
     */
    public List<MathModel> getAllModels() {
        return modelRepository.findAll();
    }
}

// --- 模型类 ---
package com.example.mathsim.model;

import javax.persistence.*;

@Entity
@Table(name = "math_models")
public class MathModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "model_name")
    private String name;

    @Column(name = "model_description")
    private String description;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// --- Thymeleaf模板（model_list.html）---
/*<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>模型列表</title>
</head>
<body>
    <h1>数学模型列表</h1>
    <table border="1">
        <tr>
            <th>模型名称</th>
            <th>描述</th>
        </tr>
        <tr th:each="model : ${models}">
            <td>
                <!-- 漏洞点：直接插入用户输入到HTML属性值中 -->
                <input type="text" th:value="${model.name}" readonly/>
            </td>
            <td th:text="${model.description}"></td>
        </tr>
    </table>
    <a href="/models/create">创建新模型</a>
</body>
</html>*/