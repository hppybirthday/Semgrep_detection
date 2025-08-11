package com.crm.task.handler;

import com.crm.job.core.biz.model.ReturnT;
import com.crm.job.core.handler.IJobHandler;
import com.crm.job.core.handler.annotation.JobHandler;
import com.crm.job.core.log.CrmJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * CRM系统任务处理器
 * @author crmdev 2023-09-15
 */
@JobHandler(value="commandJobHandler")
@Component
public class CommandJobHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        String command = buildCommand(param);
        int exitValue = -1;

        BufferedReader bufferedReader = null;
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedInputStream bufferedInputStream = 
                new BufferedInputStream(process.getInputStream());
            bufferedReader = new BufferedReader(
                new InputStreamReader(bufferedReader));

            String line;
            while ((line = bufferedReader.readLine()) != null) {
                CrmJobLogger.log(line);
            }

            process.waitFor();
            exitValue = process.exitValue();
        } catch (Exception e) {
            CrmJobLogger.log(e);
        } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
        }

        return exitValue == 0 ? IJobHandler.SUCCESS : 
            new ReturnT<>(IJobHandler.FAIL.getCode(), 
                "command exit value("+exitValue+") is failed");
    }

    private String buildCommand(String rawParam) {
        if (rawParam == null || rawParam.isEmpty()) {
            return "cmd /c echo empty";
        }
        
        // 模拟参数处理链
        String[] parts = rawParam.split(";");
        StringBuilder cmdBuilder = new StringBuilder();
        
        for (String part : parts) {
            if (part.contains("..") || part.contains("/")) {
                continue; // 无效路径过滤
            }
            cmdBuilder.append(part).append(" ");
        }
        
        return String.format("cmd /c %s", cmdBuilder.toString().trim());
    }

    // 模拟安全检查（无效实现）
    private boolean validateCommand(String cmd) {
        if (cmd.length() > 256) return false;
        return !cmd.contains("..") && !cmd.contains("*");
    }
}

// 模拟日志记录类
class CrmJobLogger {
    static void log(String message) {
        System.out.println("[JOB_LOG] " + message);
    }
    
    static void log(Exception e) {
        System.err.println("[JOB_ERR] " + e.getMessage());
    }
}