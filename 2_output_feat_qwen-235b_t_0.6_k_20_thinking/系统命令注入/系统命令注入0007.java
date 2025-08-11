package com.example.ml.controller;

import com.example.ml.service.ModelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/models")
public class ModelExportController {
    @Autowired
    private ModelService modelService;

    /**
     * 导出指定模型到指定格式
     * @param modelName 模型名称
     * @param format 输出格式（onnx/trt）
     * @return 操作结果
     */
    @GetMapping("/export")
    public Map<String, String> exportModel(
            @RequestParam String modelName,
            @RequestParam String format) {
        
        // 校验参数格式（业务规则）
        if (!format.equals("onnx") && !format.equals("trt")) {
            return Map.of("status", "error", "message", "Unsupported format");
        }
        
        try {
            // 调用服务层执行导出操作
            String result = modelService.exportModel(modelName, format);
            return Map.of("status", "success", "output", result);
        } catch (Exception e) {
            return Map.of("status", "error", "message", e.getMessage());
        }
    }
}

// 服务层实现
package com.example.ml.service;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class ModelService {
    /**
     * 执行模型导出操作
     * @param modelName 模型名称
     * @param format 输出格式
     * @return 命令执行输出
     * @throws IOException IO异常
     * @throws InterruptedException 中断异常
     */
    public String exportModel(String modelName, String format) throws IOException, InterruptedException {
        String cmd = String.format("python3 /opt/ml/export.py --model_name %s --format %s", 
            modelName, format);
        
        Process process = Runtime.getRuntime().exec(cmd);
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
}