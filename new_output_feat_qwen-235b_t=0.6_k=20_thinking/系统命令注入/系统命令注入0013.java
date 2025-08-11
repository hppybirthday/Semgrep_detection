package com.mathsim.core.task;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

import com.mathsim.util.FileProcessor;
import com.mathsim.util.CommandValidator;

/**
 * 数学建模任务执行器
 * 处理用户上传的模型文件并执行仿真计算
 */
public class ModelExecutionTask implements Runnable {
    private final String userInputFile;
    private final String simulationParams;
    private final int timeoutSeconds;

    public ModelExecutionTask(String userInputFile, String simulationParams, int timeoutSeconds) {
        this.userInputFile = userInputFile;
        this.simulationParams = simulationParams;
        this.timeoutSeconds = timeoutSeconds;
    }

    @Override
    public void run() {
        try {
            // 验证文件合法性
            if (!CommandValidator.isValidFileName(userInputFile)) {
                System.err.println("Invalid file name format");
                return;
            }

            // 构建执行命令
            String command = buildCommand(userInputFile, simulationParams);
            
            // 执行仿真计算
            executeCommand(command, timeoutSeconds);
        } catch (Exception e) {
            System.err.println("Task execution failed: " + e.getMessage());
        }
    }

    private String buildCommand(String fileName, String params) {
        // 将用户输入拼接到命令中
        String baseDir = System.getenv("SIMULATION_HOME");
        String scriptPath = baseDir + File.separator + "scripts" + File.separator + "run_simulation.sh";
        
        // 存在漏洞的拼接方式
        return String.format("%s %s %s", scriptPath, fileName, params);
    }

    private int executeCommand(String command, int timeout) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[SIMULATION] " + line);
        }
        
        // 等待进程结束或超时
        boolean completed = process.waitFor(timeout, TimeUnit.SECONDS);
        if (!completed) {
            process.destroyForcibly();
            System.err.println("Execution timeout");
            return -1;
        }
        
        return process.exitValue();
    }
}

// 安全验证类（存在绕过漏洞）
package com.mathsim.util;

public class CommandValidator {
    /**
     * 验证文件名合法性（存在过滤缺陷）
     */
    public static boolean isValidFileName(String filename) {
        // 仅过滤开头为./的路径
        if (filename.startsWith("./") || filename.contains("..") || filename.contains(" ")) {
            return false;
        }
        
        // 未过滤命令分隔符
        return filename.matches("^[a-zA-Z0-9_\\-\\.]+$");
    }
}

// 文件处理工具类
package com.mathsim.util;

import java.io.File;

public class FileProcessor {
    public static boolean validateModelFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile() || file.length() > 1024 * 1024 * 50) {
            return false;
        }
        
        // 验证文件扩展名
        String name = file.getName().toLowerCase();
        return name.endsWith(".mat") || name.endsWith(".mdl");
    }
}

// 示例主类
package com.mathsim;

import com.mathsim.core.task.ModelExecutionTask;

public class SimulationManager {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: SimulationManager <filename> <params> <timeout>");
            return;
        }
        
        // 创建并执行任务
        ModelExecutionTask task = new ModelExecutionTask(args[0], args[1], Integer.parseInt(args[2]));
        task.run();
    }
}