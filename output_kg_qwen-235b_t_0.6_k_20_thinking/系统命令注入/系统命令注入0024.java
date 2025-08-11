package com.example.ml;

import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
@RequestMapping("/api/ml")
public class MachineLearningController {

    @PostMapping("/train")
    public String trainModel(@RequestParam String datasetPath) {
        try {
            String result = MLUtil.executeCommand(datasetPath);
            return "Training completed. Output: " + result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class MLUtil {

    public static String executeCommand(String datasetPath) throws IOException {
        // 输入验证（存在缺陷）
        if (!isValidPath(datasetPath)) {
            throw new IllegalArgumentException("Invalid dataset path");
        }

        // 构造命令字符串（存在漏洞）
        String command = "python /scripts/train_model.py --dataset " + datasetPath;
        Process process = Runtime.getRuntime().exec(command);

        // 读取输出流
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }

        // 等待进程结束
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Command exited with code " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command interrupted", e);
        }

        return output.toString();
    }

    // 错误的输入验证函数
    private static boolean isValidPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        // 错误地允许字母数字、下划线、斜杠、点号和分号
        return path.matches("[a-zA-Z0-9_./;\\\\-]+");
    }
}