package com.mathsim.core.engine;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SimulationCommandExecutor {
    private static final Logger logger = LoggerFactory.getLogger(SimulationCommandExecutor.class);
    private static final String CMD_PREFIX = "python3";
    private static final String SCRIPT_PATH = "/opt/mathsim/scripts/run_simulation.py";
    
    public ExecutionResult executeSimulation(String modelName, String params) throws IOException, InterruptedException {
        if (!validateModelName(modelName)) {
            throw new IllegalArgumentException("Invalid model name");
        }
        
        List<String> paramList = parseParameters(params);
        String safeParams = sanitizeParameters(paramList);
        
        String command = CMD_PREFIX + " " + SCRIPT_PATH + " " + modelName + " " + safeParams;
        logger.info("Executing command: {}", command);
        
        Process process = Runtime.getRuntime().exec(command);
        process.waitFor();
        
        return new ExecutionResult(
            readStream(process.getInputStream()),
            readStream(process.getErrorStream()),
            process.exitValue()
        );
    }
    
    private boolean validateModelName(String modelName) {
        // Allow alphanumeric with underscores and hyphens
        return modelName != null && modelName.matches("[a-zA-Z0-9\\-_]+$$");
    }
    
    private List<String> parseParameters(String params) {
        if (!StringUtils.hasText(params)) {
            return List.of();
        }
        return Arrays.asList(params.split(","));
    }
    
    private String sanitizeParameters(List<String> params) {
        // Security measure: filter out potential dangerous characters
        return params.stream()
            .map(param -> param.replaceAll("[;|&]", ""))
            .collect(Collectors.joining(" "));
    }
    
    private String readStream(java.io.InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(inputStream)
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
    
    public static class ExecutionResult {
        private final String stdout;
        private final String stderr;
        private final int exitCode;
        
        public ExecutionResult(String stdout, String stderr, int exitCode) {
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
        }
        
        // Getters omitted for brevity
    }
}

// Controller layer (simulated)
package com.mathsim.web.controller;

import com.mathsim.core.engine.SimulationCommandExecutor;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/simulations")
@Api(tags = "Simulation Management")
public class SimulationController {
    private static final Logger logger = LoggerFactory.getLogger(SimulationController.class);
    
    @Autowired
    private SimulationCommandExecutor executor;
    
    @PostMapping("/run")
    @ApiOperation("Run simulation model")
    public SimulationResponse runSimulation(@RequestParam String modelName, 
                                          @RequestParam String params) {
        try {
            SimulationCommandExecutor.ExecutionResult result = executor.executeSimulation(modelName, params);
            return new SimulationResponse("SUCCESS", result.stdout, result.stderr, result.exitCode);
        } catch (Exception e) {
            logger.error("Simulation execution failed", e);
            return new SimulationResponse("ERROR", "", e.getMessage(), -1);
        }
    }
    
    private static class SimulationResponse {
        private final String status;
        private final String output;
        private final String error;
        private final int code;
        
        public SimulationResponse(String status, String output, String error, int code) {
            this.status = status;
            this.output = output;
            this.error = error;
            this.code = code;
        }
    }
}