package com.example.vulnerable.service;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Arrays;

/**
 * @Description: 高抽象建模的命令执行服务
 * @Author: security-expert
 */
@Service
public class CommandExecutionService {
    private static final Logger logger = LoggerFactory.getLogger(CommandExecutionService.class);

    public String executeUserCommand(String baseCommand, String userArg) throws IOException, InterruptedException {
        String[] command = constructCommand(baseCommand, userArg);
        Process process = Runtime.getRuntime().exec(command);
        
        // 异步处理输出流
        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), "STDOUT");
        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), "STDERR");
        outputGobbler.start();
        errorGobbler.start();

        int exitCode = process.waitFor();
        outputGobbler.join();
        errorGobbler.join();
        
        return String.format("Execution completed with exit code %d. Output: %s", 
                           exitCode, outputGobbler.getOutput());
    }

    private String[] constructCommand(String baseCommand, String userArg) {
        // 危险的命令构造逻辑
        logger.info("Constructing command with user input: {} {}", baseCommand, userArg);
        return new String[]{"/bin/sh", "-c", baseCommand + " " + userArg};
    }

    // 流处理内部类
    private static class StreamGobbler extends Thread {
        private InputStream inputStream;
        private String streamType;
        private StringBuilder output = new StringBuilder();

        StreamGobbler(InputStream inputStream, String streamType) {
            this.inputStream = inputStream;
            this.streamType = streamType;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                    logger.debug("[{}] {}", streamType, line);
                }
            } catch (IOException e) {
                logger.error("Stream processing error: {}", e.getMessage());
            }
        }

        String getOutput() {
            return output.toString();
        }
    }
}

// Controller层示例（简化版）
@RestController
@RequestMapping("/api/commands")
class CommandController {
    private final CommandExecutionService commandService;

    @GetMapping("/run")
    public String runCommand(@RequestParam String cmd, @RequestParam String arg) {
        try {
            return commandService.executeUserCommand(cmd, arg);
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}