package com.example.bigdata.processor;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/data")
public class DataProcessorController {
    private static final Logger logger = LoggerFactory.getLogger(DataProcessorController.class);

    @GetMapping("/process")
    public String processData(@RequestParam String inputPath, @RequestParam String outputPath) {
        Process process = null;
        try {
            // 模拟大数据处理命令构建（存在漏洞）
            String command = "hadoop jar /opt/processing.jar com.example.JobRunner "
                           + "--input " + inputPath
                           + " --output " + outputPath
                           + " && echo \\"Processing completed\\"";

            logger.info("Executing command: {}", command);
            
            // 漏洞点：直接使用拼接字符串执行命令
            process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", command});
            
            // 模拟输出处理
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            StringBuilder output = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            while ((line = errorReader.readLine()) != null) {
                logger.error("Command error: {}", line);
                output.append("[ERROR] ").append(line).append("\
");
            }
            
            process.waitFor(10, TimeUnit.SECONDS);
            return output.toString();
            
        } catch (Exception e) {
            logger.error("Command execution failed", e);
            return "Error: " + e.getMessage();
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    // 模拟数据校验接口（未实际使用）
    @GetMapping("/validate")
    public String validateData(@RequestParam String path) {
        // 实际未实现安全校验
        return "Validation not implemented";
    }

    // 模拟监控接口
    @GetMapping("/health")
    public String checkHealth() {
        return "{\\"status\\":\\"healthy\\"}";
    }
}