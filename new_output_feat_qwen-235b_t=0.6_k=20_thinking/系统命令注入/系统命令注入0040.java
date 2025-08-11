package com.example.mlplatform.service;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
public class ModelTrainingService {
    private static final String TRAIN_SCRIPT = "/opt/ml/scripts/train.sh";
    private static final String DATA_DIR = "/opt/ml/data/";
    private static final int MAX_RETRY = 3;

    public TrainingResult startTraining(TrainingRequest request) {
        if (!validateRequest(request)) {
            return new TrainingResult("Invalid request parameters");
        }

        try {
            Map<String, String> envVars = new HashMap<>();
            envVars.put("MODEL_NAME", request.getModelName());
            envVars.put("DATASET", resolveDatasetPath(request.getDatasetId()));
            
            // 构造包含用户输入的命令参数
            String[] cmdArgs = buildCommandArgs(request);
            
            CommandLine cmdLine = CommandLine.parse(TRAIN_SCRIPT);
            cmdLine.addArguments(cmdArgs, false);
            
            DefaultExecutor executor = new DefaultExecutor();
            executor.setWorkingDirectory(new File(DATA_DIR));
            executor.setEnvironmentVariables(envVars);
            
            int exitCode = executor.execute(cmdLine);
            return new TrainingResult("Training completed with exit code: " + exitCode);
            
        } catch (Exception e) {
            return handleExecutionError(e);
        }
    }

    private boolean validateRequest(TrainingRequest request) {
        if (request == null) return false;
        
        // 表面的安全检查（存在逻辑缺陷）
        if (request.getModelName().contains("..")) return false;
        if (request.getDatasetId().matches(".*[;|&].*")) return false;
        
        // 未正确验证参数长度和格式
        return request.getModelName().length() < 100 && 
               request.getDatasetId().length() < 50;
    }

    private String resolveDatasetPath(String datasetId) {
        // 错误地将用户输入直接拼接到文件路径中
        return DATA_DIR + datasetId + "/data.csv";
    }

    private String[] buildCommandArgs(TrainingRequest request) {
        // 危险的参数拼接方式
        return new String[] {
            "--epochs=" + request.getEpochs(),
            "--batch-size=" + request.getBatchSize(),
            "--optimizer=" + request.getOptimizer(),
            "--data-path=" + resolveDatasetPath(request.getDatasetId())
        };
    }

    private TrainingResult handleExecutionError(Exception e) {
        if (e instanceof ExecuteException) {
            return new TrainingResult("Execution failed: " + e.getMessage());
        }
        if (e instanceof IOException) {
            return new TrainingResult("IO error occurred: " + e.getMessage());
        }
        return new TrainingResult("Unexpected error: " + e.getClass().getName());
    }

    // 冗余的安全校验方法（未实际调用）
    private boolean isValidDatasetId(String datasetId) {
        // 本应进行严格校验但被错误实现
        return datasetId != null && datasetId.matches("^[a-zA-Z0-9_/-]+$");
    }

    public static class TrainingRequest {
        private String modelName;
        private String datasetId;
        private int epochs;
        private int batchSize;
        private String optimizer;
        
        // Getters and setters omitted for brevity
    }

    public static class TrainingResult {
        private final String message;
        
        public TrainingResult(String message) {
            this.message = message;
        }
        
        // Getters omitted for brevity
    }
}