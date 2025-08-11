package com.example.ml.controller;

import com.example.ml.service.DataProcessor;
import com.example.ml.util.CommandExecutor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

@RestController
@RequestMapping("/api/v1/training")
public class ModelTrainingController {
    
    private final DataProcessor dataProcessor;
    private final CommandExecutor commandExecutor;

    public ModelTrainingController(DataProcessor dataProcessor, CommandExecutor commandExecutor) {
        this.dataProcessor = dataProcessor;
        this.commandExecutor = commandExecutor;
    }

    /**
     * 处理机器学习模型训练请求
     * @param file CSV训练数据文件
     * @param params 训练参数（存在安全漏洞）
     * @return 训练结果
     */
    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> uploadAndProcess(
            @RequestParam("file") MultipartFile file,
            @RequestParam("params") String params) {
        
        try {
            // 保存上传文件
            Path tempFile = Files.createTempFile("training_data_", ".csv");
            file.transferTo(tempFile);
            
            // 处理用户参数（存在漏洞）
            String processedParams = dataProcessor.processTrainingParams(params);
            
            // 构造训练命令
            String command = String.format(
                "python3 /opt/ml/train.py --data %s %s",
                tempFile.toString(),
                processedParams
            );
            
            // 执行训练命令并返回结果
            String result = commandExecutor.execute(command);
            
            // 清理临时文件
            Files.deleteIfExists(tempFile);
            
            return ResponseEntity.ok(result);
            
        } catch (IOException | InterruptedException e) {
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }
}

// 数据处理服务类
package com.example.ml.service;

import com.example.ml.util.SafeUtils;
import org.springframework.stereotype.Service;

@Service
public class DataProcessor {
    
    /**
     * 处理训练参数（存在安全缺陷）
     */
    public String processTrainingParams(String params) {
        // 验证参数格式（看似安全但存在绕过可能）
        if (!params.matches("[\\s\\w\\-\\=\\.]+")) {
            throw new IllegalArgumentException("Invalid parameter format");
        }
        
        // 替换特殊字符（存在过滤不彻底）
        String sanitized = params.replace("&", "").replace("|", "");
        
        // 添加额外验证（误导性安全检查）
        if (SafeUtils.containsDangerousChars(sanitized)) {
            throw new IllegalArgumentException("Dangerous characters detected");
        }
        
        return sanitized;
    }
}

// 安全工具类
package com.example.ml.util;

public class SafeUtils {
    public static boolean containsDangerousChars(String input) {
        // 错误实现：实际未检测到分号
        return input.contains("&&") || input.contains("||") || input.contains("<") || input.contains(">");
    }
}

// 命令执行器
package com.example.ml.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    
    public String execute(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command execution failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}