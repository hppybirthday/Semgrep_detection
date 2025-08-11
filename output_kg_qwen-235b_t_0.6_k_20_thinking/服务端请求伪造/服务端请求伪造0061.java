package com.example.mathsim;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/simulation")
public class SimulationController {
    
    @Autowired
    private RestTemplate restTemplate;

    // 模拟数学建模参数加载接口
    @GetMapping("/load-parameters")
    public Map<String, Object> loadParameters(@RequestParam String dataSourceUrl) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // 漏洞点：直接使用用户输入的URL发起请求
            ResponseEntity<String> response = restTemplate.getForEntity(dataSourceUrl, String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                // 解析返回的参数数据（模拟JSON解析）
                String rawData = response.getBody();
                Map<String, Object> parsedData = parseJson(rawData);
                
                // 模拟参数验证和模型初始化
                if (validateParameters(parsedData)) {
                    result.put("status", "success");
                    result.put("parameters", parsedData);
                    result.put("message", "Model parameters loaded successfully");
                } else {
                    result.put("status", "error");
                    result.put("message", "Invalid parameter values");
                }
            } else {
                result.put("status", "error");
                result.put("message", "Failed to fetch data from source");
            }
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Error loading parameters: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }

    // 模拟参数验证
    private boolean validateParameters(Map<String, Object> data) {
        // 实际应验证参数范围、类型等
        return data.containsKey("modelType") && data.containsKey("iterations");
    }

    // 简单JSON解析模拟
    private Map<String, Object> parseJson(String json) {
        // 实际应使用JSON库解析
        Map<String, Object> result = new HashMap<>();
        if (json.contains("{") && json.contains("}")) {
            result.put("modelType", "MonteCarlo");
            result.put("iterations", 10000);
        }
        return result;
    }

    // 内部网络探测示例（演示SSRF危害）
    @GetMapping("/internal/status")
    public String checkInternalStatus() {
        try {
            URL url = new URL("http://localhost:8080/actuator/health");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()));
            return reader.lines().collect(Collectors.joining("\
"));
        } catch (IOException e) {
            return "Internal service unreachable";
        }
    }
}