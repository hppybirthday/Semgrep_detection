package com.example.mathmodelling.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 数学模型领域对象
 */
public class MathModel implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String modelName;
    private List<Double> parameters = new ArrayList<>();
    private transient double resultCache;

    public MathModel(String modelName) {
        this.modelName = modelName;
    }

    public void addParameter(double param) {
        parameters.add(param);
    }

    public double calculate() {
        // 模拟复杂计算
        resultCache = 0;
        for (Double param : parameters) {
            resultCache += param * Math.random();
        }
        return resultCache;
    }

    public String getModelName() {
        return modelName;
    }

    public List<Double> getParameters() {
        return parameters;
    }
}

// -----------------------------
package com.example.mathmodelling.service;

import com.example.mathmodelling.model.MathModel;
import java.io.*;
import java.util.Base64;

/**
 * 领域服务：模型持久化服务
 */
public class ModelPersistenceService {
    
    /**
     * 从Base64编码的序列化数据恢复模型
     */
    public MathModel restoreModel(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            // 不安全的反序列化操作
            return (MathModel) ois.readObject();
        }
    }

    /**
     * 保存模型为Base64编码的序列化数据
     */
    public String saveModel(MathModel model) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(model);
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        }
    }
}

// -----------------------------
package com.example.mathmodelling.controller;

import com.example.mathmodelling.model.MathModel;
import com.example.mathmodelling.service.ModelPersistenceService;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * 应用层控制器
 */
@RestController
@RequestMapping("/models")
public class MathModelController {
    
    private final ModelPersistenceService persistenceService = new ModelPersistenceService();

    @PostMapping("/restore")
    public String restoreModel(@RequestParam String data) {
        try {
            MathModel model = persistenceService.restoreModel(data);
            return "Model restored: " + model.getModelName() + ", Parameters: " + model.getParameters().size();
        } catch (Exception e) {
            return "Error restoring model: " + e.getMessage();
        }
    }

    @GetMapping("/{name}")
    public String createAndSaveModel(@PathVariable String name) throws IOException {
        MathModel model = new MathModel(name);
        model.addParameter(3.14);
        model.addParameter(2.718);
        
        String savedData = persistenceService.saveModel(model);
        return String.format("Model saved: %s, Data size: %d bytes",
                           name, savedData.length());
    }
}