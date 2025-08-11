package com.example.mathsim;

import java.io.*;
import java.util.*;
import java.util.logging.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SimulationController {
    private static final Logger logger = Logger.getLogger(SimulationController.class.getName());

    @GetMapping("/simulate")
    public String runSimulation(@RequestParam String modelParams) {
        StringBuilder output = new StringBuilder();
        ProcessBuilder processBuilder = new ProcessBuilder();
        // 漏洞点：直接拼接用户输入到命令中
        String command = String.format("python /opt/models/simulate.py %s", modelParams);
        processBuilder.command("bash", "-c", command);
        
        try {
            Process process = processBuilder.start();
            StreamGobbler inputGobbler = new StreamGobbler(process.getInputStream(), output);
            Thread inputThread = new Thread(inputGobbler);
            inputThread.start();
            
            StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), output);
            Thread errorThread = new Thread(errorGobbler);
            errorThread.start();
            
            int exitCode = process.waitFor();
            inputThread.join();
            errorThread.join();
            logger.info("Simulation exited with code " + exitCode);
        } catch (IOException | InterruptedException e) {
            logger.severe("Simulation failed: " + e.getMessage());
            return "Simulation execution failed.";
        }
        return output.toString();
    }

    private static class StreamGobbler implements Runnable {
        private InputStream inputStream;
        private StringBuilder output;

        public StreamGobbler(InputStream inputStream, StringBuilder output) {
            this.inputStream = inputStream;
            this.output = output;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            } catch (IOException e) {
                // 处理异常
            }
        }
    }
}