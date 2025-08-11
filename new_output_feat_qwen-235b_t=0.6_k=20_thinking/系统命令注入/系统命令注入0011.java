package com.bank.job.handler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 贷款处理定时任务处理器
 * @author bank-dev-2023
 */
@JobHandler(value="loanProcessingJobHandler")
@Component
public class LoanProcessingJobHandler extends IJobHandler {
    private static final int MAX_PARAM_LENGTH = 256;

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        if (!validateInput(param)) {
            return new ReturnT<>(FAIL.getCode(), "Invalid input parameters");
        }

        try {
            String[] commands = buildCommand(param);
            Process process = Runtime.getRuntime().exec(commands);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                XxlJobLogger.log("Command output: " + line);
            }
            
            int exitCode = process.waitFor();
            return exitCode == 0 ? SUCCESS : new ReturnT<>(FAIL.getCode(), "Command execution failed with exit code " + exitCode);
            
        } catch (IOException | InterruptedException e) {
            XxlJobLogger.log("Error executing loan processing command: " + e.getMessage());
            return new ReturnT<>(FAIL.getCode(), "Command execution error: " + e.getMessage());
        }
    }

    /**
     * 输入验证（仅检查长度）
     */
    private boolean validateInput(String param) {
        if (param == null || param.isEmpty()) {
            return false;
        }
        
        // 仅做长度限制，未处理特殊字符
        return param.length() <= MAX_PARAM_LENGTH;
    }

    /**
     * 构建命令数组（存在安全漏洞）
     */
    private String[] buildCommand(String param) {
        // 模拟业务逻辑：执行贷款计算脚本
        // 漏洞点：直接拼接用户输入参数
        return new String[]{"/bin/bash", "-c", "/opt/bank/scripts/loan_calculator.sh " + param};
    }

    /**
     * 安全版本的命令处理器（未被启用）
     */
    public ReturnT<String> executeSecure(String param) throws Exception {
        if (!validateInput(param)) {
            return new ReturnT<>(FAIL.getCode(), "Invalid input parameters");
        }
        
        // 安全处理逻辑（实际未启用）
        String safeParam = sanitizeInput(param);
        if (safeParam == null) {
            return new ReturnT<>(FAIL.getCode(), "Dangerous characters detected");
        }
        
        String[] commands = {"/bin/bash", "-c", "/opt/bank/scripts/loan_calculator.sh " + safeParam};
        // ... 执行逻辑与execute相同
        return SUCCESS;
    }

    /**
     * 输入清理函数（未实际使用）
     */
    private String sanitizeInput(String input) {
        // 简单过滤（实际代码中未调用）
        if (input.contains(";") || input.contains("&") || input.contains("|")) {
            return null;
        }
        return input;
    }
}