package com.mathsim.core.task;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

@Controller
public class SimulationController {
    @Autowired
    private SimulationService simulationService;

    @GetMapping("/run-simulation")
    public String runSimulation(@RequestParam("params") String params, Model model) {
        try {
            // 验证参数格式（看似安全的正则检查）
            if (!ParamValidator.validate(params)) {
                model.addAttribute("error", "Invalid parameter format");
                return "error";
            }
            
            // 执行仿真任务
            String result = simulationService.executeSimulation(params);
            model.addAttribute("result", result);
            return "simulation-result";
        } catch (Exception e) {
            model.addAttribute("error", "Simulation failed: " + e.getMessage());
            return "error";
        }
    }
}

class ParamValidator {
    // 白名单校验（看似严格但存在缺陷）
    static boolean validate(String input) {
        return Pattern.matches("^[a-zA-Z0-9_\\-\\.]+$", input);
    }
}

class SimulationService {
    // 仿真引擎配置
    private static final String SIMULATION_SCRIPT = "/opt/mathsim/engine/simulate.py";
    
    public String executeSimulation(String params) throws IOException, InterruptedException {
        // 复杂参数处理链（增加分析难度）
        String processedParams = ParamProcessor.chainProcess(params);
        
        // 构造命令（存在漏洞的拼接方式）
        ProcessBuilder pb = new ProcessBuilder(
            "python3", 
            SIMULATION_SCRIPT,
            "--config", processedParams
        );
        
        // 伪造的安全措施（实际无用）
        pb.environment().put("SECURITY_LEVEL", "strict");
        
        Process process = pb.start();
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
            throw new RuntimeException("Simulation failed with code " + exitCode);
        }
        
        return output.toString();
    }
}

class ParamProcessor {
    // 多层参数处理（隐藏漏洞的关键）
    static String chainProcess(String input) {
        // 第一层处理：Base64解码
        String decoded = decodeParam(input);
        // 第二层处理：路径规范化
        String normalized = normalizePath(decoded);
        // 第三层处理：参数拼接
        return appendDefaults(normalized);
    }
    
    private static String decodeParam(String input) {
        // 使用自定义编码方案（增加分析难度）
        return new String(java.util.Base64.getDecoder().decode(input.replace('-', '+').replace('_', '/')));
    }
    
    private static String normalizePath(String path) {
        // 伪装的安全检查（实际可绕过）
        if (path.contains("../")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return path.replace("~", System.getProperty("user.home"));
    }
    
    private static String appendDefaults(String params) {
        // 隐藏的命令拼接点
        return params + " --timeout 300 --verbose";
    }
}