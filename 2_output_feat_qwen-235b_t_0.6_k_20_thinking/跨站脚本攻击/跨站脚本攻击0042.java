package com.example.mlplatform.controller;

import com.example.mlplatform.service.ModelService;
import com.example.mlplatform.model.ModelInfo;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 模型管理控制器
 * 处理模型上传和展示逻辑
 */
@Controller
@RequestMapping("/models")
public class ModelController {
    private final ModelService modelService;

    public ModelController(ModelService modelService) {
        this.modelService = modelService;
    }

    /**
     * 显示模型上传表单
     */
    @GetMapping("/upload")
    public String showUploadForm(Model model) {
        model.addAttribute("modelInfo", new ModelInfo());
        return "upload-form";
    }

    /**
     * 处理模型上传请求
     * @param modelInfo 模型信息
     */
    @PostMapping("/upload")
    public String handleModelUpload(@ModelAttribute ModelInfo modelInfo) {
        // 调用服务层保存模型信息
        modelService.saveModelInfo(modelInfo);
        return "redirect:/models/list";
    }

    /**
     * 展示模型列表
     */
    @GetMapping("/list")
    public String listModels(Model model) {
        List<ModelInfo> models = modelService.getAllModels();
        model.addAttribute("models", models);
        return "model-list";
    }
}

package com.example.mlplatform.service;

import com.example.mlplatform.model.ModelInfo;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 模型信息服务类
 * 处理模型信息的存储和检索
 */
@Service
public class ModelService {
    private final List<ModelInfo> modelDatabase = new ArrayList<>();

    /**
     * 保存模型信息
     * @param modelInfo 模型信息
     */
    public void saveModelInfo(ModelInfo modelInfo) {
        // 模拟数据库存储
        modelDatabase.add(modelInfo);
    }

    /**
     * 获取所有模型信息
     */
    public List<ModelInfo> getAllModels() {
        return new ArrayList<>(modelDatabase);
    }
}

package com.example.mlplatform.model;

/**
 * 模型信息实体类
 */
public class ModelInfo {
    private String modelName;
    private String description;

    // Getters and Setters
    public String getModelName() {
        return modelName;
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}

// Thymeleaf模板：src/main/resources/templates/model-list.html
// <div th:each="model : ${models}">
//   <h3 th:text="${model.modelName}"></h3>
//   <p th:text="${model.description}"></p>
// </div>