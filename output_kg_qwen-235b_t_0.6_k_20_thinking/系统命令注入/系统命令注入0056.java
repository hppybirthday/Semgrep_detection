package com.example.ml.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainingController {
    
    // 模拟机器学习模型训练接口
    // 漏洞点：直接拼接用户输入到系统命令中
    @GetMapping("/train")
    public String trainModel(@RequestParam String datasetPath, 
                           @RequestParam String modelOutputPath) throws Exception {
        
        // 记录训练参数（模拟实际开发中的日志记录）
        System.out.println("[INFO] 接收到训练请求");
        System.out.println("Dataset Path: " + datasetPath);
        System.out.println("Model Output Path: " + modelOutputPath);
        
        // 构建执行命令（存在漏洞的关键点）
        String pythonScript = "train_script.py";
        String command = String.format("python %s --data %s --output %s", 
            pythonScript, datasetPath, modelOutputPath);
        
        // 模拟执行系统命令
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        while ((line = errorReader.readLine()) != null) {
            output.append("[ERROR] ").append(line).append("\
");
        }
        
        // 返回执行结果
        return output.toString();
    }
    
    // 模拟训练脚本（实际不存在，仅用于演示）
    @GetMapping("/create_script")
    public String createTrainingScript() {
        String scriptContent = "import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('--data', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()

# 模拟训练过程
os.makedirs(args.output, exist_ok=True)
with open(os.path.join(args.output, 'model.pth'), 'w') as f:
    f.write('simulated model data')
print(f'Training completed. Model saved to {args.output}')";
        
        try (FileWriter writer = new FileWriter("train_script.py")) {
            writer.write(scriptContent);
            return "Training script created successfully";
        } catch (IOException e) {
            return "Failed to create training script: " + e.getMessage();
        }
    }
    
    // 模拟的模型导出接口（存在相同漏洞）
    @GetMapping("/export")
    public String exportModel(@RequestParam String modelPath, 
                            @RequestParam String exportFormat) throws Exception {
        String command = String.format("python convert_model.py --input %s --format %s", 
            modelPath, exportFormat);
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取输出结果（简化处理）
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}