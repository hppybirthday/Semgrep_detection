package com.example.mathsim;

import java.io.*;
import java.util.*;

/**
 * 数学建模仿真引擎
 * 模拟通过外部脚本执行复杂计算的场景
 */
interface Model {
    String execute(String params) throws IOException;
}

class SimulationModel implements Model {
    @Override
    public String execute(String params) throws IOException {
        // 模拟调用外部Python脚本处理数学计算
        String command = "python3 /scripts/simulate.py " + params;
        
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取计算结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\
");
        }
        
        return result.toString();
    }
}

class ParameterResolver {
    // 解析用户输入的参数字符串
    public static Map<String, String> parseParams(String input) {
        Map<String, String> params = new HashMap<>();
        String[] pairs = input.split("&");
        
        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                params.put(keyValue[0], keyValue[1]);
            }
        }
        
        return params;
    }
}

class Simulator {
    private Model model;
    
    public Simulator(Model model) {
        this.model = model;
    }
    
    public String runSimulation(String userInput) throws IOException {
        Map<String, String> params = ParameterResolver.parseParams(userInput);
        // 漏洞点：直接将用户参数拼接到命令中
        return model.execute("--params " + userInput);
    }
}

public class MathSimApplication {
    public static void main(String[] args) {
        try {
            // 模拟用户输入
            String userInput = "a=1.5&b=2.7; rm -rf /tmp/test*";
            
            Simulator simulator = new Simulator(new SimulationModel());
            String result = simulator.runSimulation(userInput);
            
            System.out.println("计算结果：\
" + result);
            
        } catch (Exception e) {
            System.err.println("错误：" + e.getMessage());
        }
    }
}