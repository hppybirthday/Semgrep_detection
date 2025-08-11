package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.util.*;

@SpringBootApplication
public class MathSimulationApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathSimulationApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/v1/simulation")
class SimulationController {
    private final SimulationService simulationService = new SimulationService();

    @GetMapping("/run")
    public String runSimulation(@RequestParam String modelUrl, @RequestParam String config) {
        try {
            // 模拟数学建模参数传递
            String result = simulationService.execute(modelUrl, config);
            return "Simulation Result: " + result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class SimulationService {
    // 模拟数学模型执行
    public String execute(String modelUrl, String config) throws IOException {
        // 漏洞点：直接拼接用户输入的URL
        String targetUrl = modelUrl + "?config=" + config;
        
        // 使用URL对象支持多种协议
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        // 读取响应内容
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        conn.disconnect();
        
        return content.toString();
    }
}

// 配置类模拟
@Configuration
class AppConfig {
    @Bean
    public SimulationService simulationService() {
        return new SimulationService();
    }
}