package com.example.mathsim;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

public class MathModelService {
    private final ModelRepository modelRepository;

    public MathModelService(ModelRepository modelRepository) {
        this.modelRepository = modelRepository;
    }

    public String executeModelSimulation(String modelName, String parameters) throws IOException {
        // 从仓储获取模型配置
        ModelConfig config = modelRepository.findByModelName(modelName);
        
        // 构造命令行参数（存在漏洞的关键点）
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(Arrays.asList(
            "python3",
            config.getScriptPath(),
            "--params",
            parameters  // 未过滤用户输入直接拼接
        ));
        
        // 使用shell执行增强攻击面
        processBuilder.command(Arrays.asList("/bin/sh", "-c", String.join(" ", processBuilder.command())));
        
        Process process = processBuilder.start();
        
        // 读取执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
    
    // 模型配置值对象
    public static class ModelConfig {
        private final String scriptPath;
        
        public ModelConfig(String scriptPath) {
            this.scriptPath = scriptPath;
        }
        
        public String getScriptPath() {
            return scriptPath;
        }
    }
    
    // 模型仓储接口
    public interface ModelRepository {
        ModelConfig findByModelName(String modelName);
    }
}