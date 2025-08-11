package com.mathsim.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimulatorController {
    
    @Autowired
    private SimulationService simulationService;

    /**
     * 数学模型仿真接口
     * 示例请求: /run-simulation?model=lorenz&params=x0=1;y0=2;z0=3;time=100
     */
    @GetMapping("/run-simulation")
    public String runSimulation(@RequestParam String model, @RequestParam String params) {
        try {
            // 执行模型仿真
            return simulationService.executeModel(model, params);
        } catch (Exception e) {
            return "Error executing simulation: " + e.getMessage();
        }
    }
}

class SimulationService {
    
    // MATLAB脚本模板
    private static final String MATLAB_SCRIPT = "function result = %s_model(%s)\
" + 
        "    %s\
" + 
        "    result = simulate_model(%s);\
" + 
        "endfunction";
    
    // 仿真参数白名单
    private static final Pattern PARAM_PATTERN = Pattern.compile("[a-zA-Z0-9_\\s=\\.\\-]+");

    public String executeModel(String modelName, String rawParams) throws IOException, InterruptedException {
        // 参数验证（存在绕过可能性）
        if (!validateParams(rawParams)) {
            return "Invalid simulation parameters";
        }
        
        // 构建MATLAB命令参数
        List<String> command = new ArrayList<>();
        command.add("matlab");
        command.add("-batch");
        
        // 生成并执行仿真脚本
        String script = generateScript(modelName, rawParams);
        command.add(script);
        
        // 执行仿真并获取结果
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(new File("/opt/mathsim/models"));
        Process process = processBuilder.start();
        
        // 读取输出结果
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
        return "Simulation Output:\
" + output.toString() + 
               "\
Exit Code: " + exitCode;
    }
    
    private boolean validateParams(String params) {
        // 仅允许参数包含字母数字和基本符号（存在过滤缺陷）
        return PARAM_PATTERN.matcher(params).matches();
    }
    
    private String generateScript(String modelName, String rawParams) {
        // 构建参数列表
        String[] paramsArray = rawParams.split(";");
        StringBuilder paramsBuilder = new StringBuilder();
        for (String param : paramsArray) {
            if (param.trim().isEmpty()) continue;
            // 参数拼接存在注入风险
            paramsBuilder.append(param).append(", ");
        }
        
        // 构建脚本内容
        return String.format(MATLAB_SCRIPT, 
            modelName,
            paramsBuilder.toString().replaceAll("\\\\s+,\\\\s+", ", "),
            buildModelFunction(modelName),
            paramsBuilder.toString()
        );
    }
    
    private String buildModelFunction(String modelName) {
        // 动态生成模型函数逻辑
        switch(modelName) {
            case "lorenz":
                return "dx = 10*(y-x); dy = x*(28-z)-y; dz = x*y-2.66*z";
            case "rossler":
                return "dx = -y - z; dy = x + 0.2*y; dz = 0.2 + z*(x-5.7)";
            default:
                return "error('Unknown model')";
        }
    }
}
