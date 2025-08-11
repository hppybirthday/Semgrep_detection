package com.example.mathsim;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * 数学建模仿真引擎 - 存在命令注入漏洞的实现
 */
public class VulnerableModelExecutor {
    private static final Logger logger = Logger.getLogger("ModelExecutor");

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java VulnerableModelExecutor <model-parameters>");
            return;
        }

        try {
            ModelRunner runner = new ModelRunner(args[0]);
            String result = runner.runSimulation();
            System.out.println("Simulation Result: " + result);
        } catch (Exception e) {
            logger.severe("Execution failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static class ModelRunner {
        private final String userInput;

        public ModelRunner(String userInput) {
            this.userInput = userInput;
        }

        public String runSimulation() throws IOException, InterruptedException {
            // 模拟调用外部数学工具：将用户输入作为参数传递给外部脚本
            String[] command = {"/bin/bash", "-c", "./math_tool.sh " + userInput};
            
            logger.info("Executing command: " + Arrays.toString(command));
            
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取输出流
            StreamGobbler outputGobbler = new StreamGobbler(
                process.getInputStream(), 
                "OUTPUT"
            );
            StreamGobbler errorGobbler = new StreamGobbler(
                process.getErrorStream(), 
                "ERROR"
            );
            
            Thread outputThread = new Thread(outputGobbler);
            Thread errorThread = new Thread(errorGobbler);
            
            outputThread.start();
            errorThread.start();
            
            int exitCode = process.waitFor();
            outputThread.join();
            errorThread.join();
            
            return "Exit code: " + exitCode;
        }
    }

    static class StreamGobbler implements Runnable {
        private InputStream inputStream;
        private String type;

        public StreamGobbler(InputStream inputStream, String type) {
            this.inputStream = inputStream;
            this.type = type;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(type + ": " + line);
                }
                
            } catch (IOException e) {
                logger.severe("Stream reading failed: " + e.getMessage());
            }
        }
    }
}