import java.io.*;
import java.util.*;
import java.util.function.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

class MLModelTrainer {
    static class CommandResult {
        String output;
        int exitCode;
        CommandResult(String output, int exitCode) {
            this.output = output;
            this.exitCode = exitCode;
        }
    }

    Function<String[], CommandResult> executeCommand = (cmd) -> {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
            );
            
            String output = reader.lines().collect(Collectors.joining("\
"));
            int exitCode = process.waitFor();
            return new CommandResult(output, exitCode);
        } catch (Exception e) {
            return new CommandResult(e.getMessage(), -1);
        }
    };

    BiFunction<String, String, String> trainModel = (dataPath, modelParams) -> {
        try {
            // 模拟机器学习模型训练流程
            String pythonScript = "python3";
            String scriptPath = "/opt/ml/train.py";
            
            // 存在漏洞的代码：直接拼接用户输入参数
            String[] command = {
                pythonScript,
                scriptPath,
                "--data-path=" + dataPath,
                "--params=" + modelParams
            };
            
            CommandResult result = executeCommand.apply(command);
            return String.format("Training completed with output:\
%s\
Exit code: %d",
                                 result.output, result.exitCode);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    };

    public static void main(String[] args) {
        MLModelTrainer trainer = new MLModelTrainer();
        
        if (args.length < 2) {
            System.out.println("Usage: java MLModelTrainer <data-path> <model-params>");
            return;
        }
        
        String dataPath = args[0];
        String modelParams = args[1];
        
        // 模拟机器学习模型训练
        String result = trainer.trainModel.apply(dataPath, modelParams);
        System.out.println(result);
    }
}