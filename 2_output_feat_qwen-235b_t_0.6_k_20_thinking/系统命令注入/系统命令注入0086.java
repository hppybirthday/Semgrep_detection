package com.example.mathsim.controller;

import com.example.mathsim.service.MathModelService;
import com.example.mathsim.util.Result;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.IOException;

@RestController
@RequestMapping("/model")
public class MathModelController {

    @Resource
    private MathModelService mathModelService;

    /**
     * 执行数学模型计算接口
     * 参数示例：/model/exec?modelPath=linear_regression.py&dataFile=data.csv
     */
    @GetMapping("/exec")
    public Result<String> executeModel(@RequestParam String modelPath, @RequestParam String dataFile) {
        try {
            String output = mathModelService.runModelSimulation(modelPath, dataFile);
            return Result.success(output);
        } catch (IOException | InterruptedException e) {
            return Result.error("模型执行失败: " + e.getMessage());
        }
    }
}

// com/example/mathsim/service/MathModelService.java
package com.example.mathsim.service;

import com.example.mathsim.util.CommandLineUtil;
import com.example.mathsim.util.SimulationConfig;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Service
public class MathModelService {

    private final SimulationConfig config;

    public MathModelService(SimulationConfig config) {
        this.config = config;
    }

    public String runModelSimulation(String modelPath, String dataFile) 
        throws IOException, InterruptedException {
        
        // 构建完整命令行参数
        String command = String.format("python %s %s %s",
            resolveModelPath(modelPath),
            config.getDataDir(),
            dataFile
        );

        // 执行仿真计算
        ProcessBuilder pb = CommandLineUtil.buildProcess(command);
        Process process = pb.start();
        
        // 等待执行完成并获取输出
        boolean completed = process.waitFor(30, TimeUnit.SECONDS);
        if (!completed) {
            process.destroy();
            throw new IOException("执行超时");
        }
        
        return CommandLineUtil.readProcessOutput(process.getInputStream());
    }

    private String resolveModelPath(String modelPath) {
        // 模拟路径解析逻辑
        if (modelPath.contains("..") || !modelPath.endsWith(".py")) {
            throw new IllegalArgumentException("非法模型路径");
        }
        return config.getModelDir() + modelPath;
    }
}

// com/example/mathsim/util/CommandLineUtil.java
package com.example.mathsim.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;

public class CommandLineUtil {

    public static ProcessBuilder buildProcess(String command) {
        // 使用sh -c执行命令字符串
        return new ProcessBuilder("sh", "-c", command);
    }

    public static String readProcessOutput(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(inputStream)
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

// com/example/mathsim/util/SimulationConfig.java
package com.example.mathsim.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SimulationConfig {

    @Value("${model.dataDir}")
    private String dataDir;

    @Value("${model.modelDir}")
    private String modelDir;

    public String getDataDir() {
        return dataDir;
    }

    public String getModelDir() {
        return modelDir;
    }
}

// com/example/mathsim/util/Result.java
package com.example.mathsim.util;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Result<T> {
    private boolean success;
    private T data;
    private String error;

    public static <T> Result<T> success(T data) {
        return new Result<>(true, data, null);
    }

    public static Result<?> error(String message) {
        return new Result<>(false, null, message);
    }
}