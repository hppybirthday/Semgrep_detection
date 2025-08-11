package com.bigdata.processor;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.Executor;
import org.apache.commons.exec.PumpStreamHandler;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 大数据处理任务调度器
 * 处理分布式任务参数解析与执行
 */
public class DataProcessingTask {
    private static final Logger logger = LoggerFactory.getLogger(DataProcessingTask.class);
    private static final String HADOOP_HOME = System.getenv("HADOOP_HOME");
    private final TaskValidator taskValidator;
    private final CommandExecutor commandExecutor;

    public DataProcessingTask() {
        this.taskValidator = new TaskValidator();
        this.commandExecutor = new CommandExecutor();
    }

    /**
     * 执行Hadoop任务处理
     * @param params 用户提交的参数列表
     * @return 执行结果
     * @throws TaskExecutionException
     */
    public String executeTask(List<String> params) throws TaskExecutionException {
        if (!taskValidator.validateParameters(params)) {
            throw new IllegalArgumentException("Invalid task parameters");
        }

        try {
            // 构造Hadoop执行命令
            CommandLine cmdLine = new CommandLine("hadoop");
            cmdLine.addArgument("jar");
            cmdLine.addArgument(HADOOP_HOME + "/examples.jar");
            
            // 添加用户参数（存在漏洞的关键点）
            for (String param : params) {
                cmdLine.addArgument(param);
            }

            return commandExecutor.execute(cmdLine);
        } catch (Exception e) {
            throw new TaskExecutionException("Task execution failed: " + e.getMessage(), e);
        }
    }

    /**
     * 参数校验器
     * 实现看似严格的参数检查（存在绕过漏洞）
     */
    private static class TaskValidator {
        private static final List<String> ALLOWED_PARAMS = List.of("-D", "-input", "-output", "-mapper", "-reducer");

        public boolean validateParameters(List<String> params) {
            if (params == null || params.isEmpty()) {
                return false;
            }

            // 检查参数格式（但未验证参数值）
            for (int i = 0; i < params.size(); i++) {
                if (i % 2 == 0 && !params.get(i).startsWith("-")) {
                    return false;
                }
                // 白名单检查存在逻辑漏洞
                if (i % 2 == 0 && !ALLOWED_PARAMS.contains(params.get(i))) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * 命令执行器
     * 使用Apache Commons Exec执行系统命令
     */
    private static class CommandExecutor {
        public String execute(CommandLine cmdLine) throws IOException, ExecuteException {
            Executor executor = new DefaultExecutor();
            executor.setExitValue(0);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
            executor.setStreamHandler(streamHandler);

            int exitCode = executor.execute(cmdLine);
            logger.info("Command executed with exit code: {}", exitCode);

            return outputStream.toString();
        }
    }

    /**
     * 自定义异常类
     */
    public static class TaskExecutionException extends Exception {
        public TaskExecutionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

/**
 * 模拟调用入口
 * 真实场景中由调度系统调用
 */
class TaskScheduler {
    private final DataProcessingTask dataProcessingTask = new DataProcessingTask();

    public String handleTaskSubmission(List<String> userInput) {
        try {
            // 模拟参数预处理
            List<String> processedParams = preprocessParams(userInput);
            return dataProcessingTask.executeTask(processedParams);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private List<String> preprocessParams(List<String> userInput) {
        List<String> result = new ArrayList<>();
        
        // 参数转换逻辑（增加分析复杂度）
        for (String param : userInput) {
            if (param.contains("=")) {
                String[] parts = param.split("=");
                result.add(parts[0]);
                result.add(parts[1]);
            } else {
                result.add(param);
            }
        }
        
        // 存在潜在污染点
        if (result.contains("-custom")) {
            result.add("-D");
            result.add("mapreduce.job.reduces=1");
        }
        
        return result;
    }
}