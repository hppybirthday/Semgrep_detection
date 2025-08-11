package com.example.ml;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainingController {
    
    @GetMapping("/train")
    public String trainModel(@RequestParam String datasetPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder();
            // 模拟调用Python脚本进行模型训练
            List<String> command = new ArrayList<>();
            command.add("python3");
            command.add("train_script.py");
            // 漏洞点：直接拼接用户输入
            command.add("--data=" + datasetPath);
            
            Process process = pb.command(command).start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return "Training completed with exit code " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟训练脚本
    public static void main(String[] args) {
        // 实际中会调用机器学习框架
        System.out.println("Training model...");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {}
        System.out.println("Model trained successfully");
    }
}