package com.example.mathsim;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class SimulationJobHandler {
    private static final Pattern PARAM_PATTERN = Pattern.compile("([a-zA-Z0-9_]+)=(.+)");

    public String runSimulation(String rawParams) throws IOException, InterruptedException {
        Map<String, String> params = parseParams(rawParams);
        
        // 构建仿真参数字符串
        StringBuilder paramBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            paramBuilder.append(String.format(" -%s %s", entry.getKey(), entry.getValue()));
        }
        
        // 执行仿真引擎（Windows环境）
        String command = String.format("cmd /c simulate.exe%s", paramBuilder.toString());
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 收集执行结果
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }

    private Map<String, String> parseParams(String raw) {
        Map<String, String> params = new HashMap<>();
        if (raw == null || raw.trim().isEmpty()) return params;
        
        // 解析参数格式：key1=value1;key2=value2
        for (String pair : raw.split(";")) {
            if (pair.trim().isEmpty()) continue;
            
            // 使用正则匹配键值对
            java.util.regex.Matcher matcher = PARAM_PATTERN.matcher(pair);
            if (matcher.matches()) {
                params.put(matcher.group(1), matcher.group(2));
            }
        }
        return params;
    }

    // 模拟参数校验（仅检查必要参数存在性）
    private boolean validateParams(Map<String, String> params) {
        return params.containsKey("model") && !params.get("model").isEmpty();
    }
}