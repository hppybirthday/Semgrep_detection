package com.task.manager.job.handler;

import com.task.manager.core.model.JobParams;
import com.task.manager.core.handler.IJobHandler;
import com.task.manager.core.handler.annotation.JobHandler;
import com.task.manager.core.log.JobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 任务命令处理器
 * 处理带参数的任务执行逻辑
 */
@JobHandler(value = "taskCommandHandler")
@Component
public class TaskCommandHandler extends IJobHandler {

    @Override
    public String execute(JobParams jobParams) throws IOException, InterruptedException {
        List<String> commands = new ArrayList<>();
        
        // 获取系统命令基础路径
        String baseCommand = getBaseCommand();
        commands.add(baseCommand);
        
        // 添加用户参数
        String userParam = jobParams.getUserParam();
        if (userParam != null && !userParam.isEmpty()) {
            commands.addAll(parseUserParameters(userParam));
        }
        
        // 执行命令
        ProcessBuilder processBuilder = new ProcessBuilder(commands);
        Process process = processBuilder.start();
        
        // 读取执行结果
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        // 等待进程结束
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            JobLogger.error("Command execution failed with exit code: " + exitCode);
        }
        
        return output.toString();
    }

    /**
     * 获取系统基础命令路径
     * 根据环境配置确定执行命令
     */
    private String getBaseCommand() {
        // 模拟从配置中心获取命令路径
        return System.getenv().getOrDefault("TASK_CMD_PATH", "/usr/local/bin/backup_tool");
    }

    /**
     * 解析用户参数
     * 将参数按空格分割为命令参数列表
     */
    private List<String> parseUserParameters(String userParam) {
        List<String> result = new ArrayList<>();
        // 模拟参数处理逻辑
        for (String param : userParam.split(" ")) {
            if (!param.isEmpty()) {
                result.add(param);
            }
        }
        return result;
    }
}