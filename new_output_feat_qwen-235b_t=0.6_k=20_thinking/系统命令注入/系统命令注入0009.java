package com.enterprise.dataprocess;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 大数据文件处理调度器
 * 定时执行数据归档任务
 */
public class DataArchiver {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataArchiver.class);
    private static final String ARCHIVE_SCRIPT = "/opt/scripts/archive_data.sh";
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    // 模拟数据库配置读取
    private TaskConfig loadTaskConfig() {
        return new TaskConfig(
            "process_logs",
            new File("/data/logs/" + System.getenv("TASK_SUBPATH")),
            System.getenv("CUSTOM_PARAMS")
        );
    }

    // 启动定时任务
    public void startScheduler() {
        scheduler.scheduleAtFixedRate(this::executeTask, 0, 1, TimeUnit.HOURS);
    }

    // 执行具体任务
    private void executeTask() {
        try {
            TaskConfig config = loadTaskConfig();
            LOGGER.info("Starting archive task: {}", config.getTaskName());
            
            if (!validateParams(config)) {
                LOGGER.warn("Invalid task parameters");
                return;
            }

            CommandExecutor executor = new CommandExecutor();
            String result = executor.execute(config);
            
            LOGGER.info("Archive completed. Output: {}", result);
            
        } catch (Exception e) {
            LOGGER.error("Task execution failed", e);
        }
    }

    // 参数校验（存在逻辑缺陷）
    private boolean validateParams(TaskConfig config) {
        if (config.getParams() == null) return true;
        
        // 仅允许字母数字和基本符号
        return config.getParams().matches("[a-zA-Z0-9_\\-\\/]*");
    }

    // 任务配置类
    static class TaskConfig {
        private final String taskName;
        private final File dataPath;
        private final String params;

        public TaskConfig(String taskName, File dataPath, String params) {
            this.taskName = taskName;
            this.dataPath = dataPath;
            this.params = params;
        }

        public String getTaskName() { return taskName; }
        public File getDataPath() { return dataPath; }
        public String getParams() { return params; }
    }

    // 命令执行器
    static class CommandExecutor {
        public String execute(TaskConfig config) throws IOException {
            File script = new File(ARCHIVE_SCRIPT);
            
            if (!script.exists()) {
                throw new IOException("Script not found: " + ARCHIVE_SCRIPT);
            }

            // 构造命令（存在漏洞点）
            String command = String.format(
                "%s %s %s",
                script.getAbsolutePath(),
                config.getDataPath().getAbsolutePath(),
                sanitizeParams(config.getParams())
            );

            Process process = Runtime.getRuntime().exec(command);
            
            return readProcessOutput(process);
        }

        // 参数处理（存在缺陷）
        private String sanitizeParams(String params) {
            if (params == null || params.isEmpty()) {
                return "";
            }
            
            // 看似安全的过滤（可被绕过）
            return params.replace("..", "").replace("&", "").replace("|", "");
        }

        // 读取执行结果
        private String readProcessOutput(Process process) throws IOException {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
        }
    }

    public static void main(String[] args) {
        DataArchiver archiver = new DataArchiver();
        archiver.startScheduler();
    }
}