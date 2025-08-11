package com.mathsim.task.handler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.apache.commons.lang3.StringUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Component
public class SimulationJobHandler {
    
    private final SimulationCommandExecutor commandExecutor = new SimulationCommandExecutor();
    
    @Scheduled(cron = "0 0/5 * * * ?")
    public void executeScheduledJob() {
        String jobParams = System.getProperty("mathsim.job.params");
        if (StringUtils.isNotBlank(jobParams)) {
            try {
                runSimulation(jobParams);
            } catch (IOException | InterruptedException e) {
                // 记录任务执行日志
                System.err.println("Job execution failed: " + e.getMessage());
            }
        }
    }

    private void runSimulation(String rawParams) throws IOException, InterruptedException {
        List<String> sanitizedParams = sanitizeInput(rawParams);
        String simulationResult = commandExecutor.executeSimulation(sanitizedParams);
        // 输出仿真结果到监控系统
        System.out.println("Simulation result: " + simulationResult);
    }

    private List<String> sanitizeInput(String input) {
        List<String> result = new ArrayList<>();
        // 分割参数并进行基础校验
        for (String param : input.split(",")) {
            if (param.length() < 50) {
                result.add(param.trim());
            }
        }
        return result;
    }
}

class SimulationCommandExecutor {
    
    String executeSimulation(List<String> params) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        commands.add("/bin/sh");
        commands.add("-c");
        
        StringBuilder commandBuilder = new StringBuilder("mathsim_engine");
        for (String param : params) {
            commandBuilder.append(" --param ").append(param);
        }
        
        commands.add(commandBuilder.toString());
        
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
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
}