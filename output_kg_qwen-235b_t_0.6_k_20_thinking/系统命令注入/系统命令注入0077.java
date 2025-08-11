package com.mathsim.core;

import lombok.Data;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 数学建模领域模型
 */
@Data
public class MathematicalModel {
    private String modelName;
    private String simulationParams;
    private String outputFormat;
}

/**
 * 仿真执行器（存在漏洞的实现）
 */
public class Simulator {
    public String runSimulation(MathematicalModel model) throws IOException {
        List<String> command = new ArrayList<>();
        
        // 构造数学仿真命令（漏洞点）
        command.add("matlab");
        command.add("-batch");
        // 漏洞：直接拼接用户输入参数
        command.add(String.format("runModel('%s', '%s', '%s')", 
            model.getModelName(), 
            model.getSimulationParams(),
            model.getOutputFormat()));

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 读取输出结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

/**
 * 领域服务
 */
public class SimulationService {
    public String executeModel(String modelName, String params, String format) throws IOException {
        MathematicalModel model = new MathematicalModel();
        model.setModelName(modelName);
        model.setSimulationParams(params);
        model.setOutputFormat(format);
        
        Simulator simulator = new Simulator();
        return simulator.runSimulation(model);
    }
}

/**
 * 配置仓储
 */
public class SimulationRepository {
    // 简化版内存仓储
}

/**
 * 应用层入口
 */
public class SimulatorApplication {
    public static void main(String[] args) throws IOException {
        SimulationService service = new SimulationService();
        // 示例调用（攻击者可通过参数注入命令）
        String result = service.executeModel(
            "lorenz_attractor", 
            "0.1,20,5.5; calc.exe",  // Windows示例攻击向量
            "png");
        System.out.println("仿真结果：\
" + result);
    }
}