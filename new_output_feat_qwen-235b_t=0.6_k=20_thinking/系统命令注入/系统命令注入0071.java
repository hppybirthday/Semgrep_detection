package com.bigdata.processor.job;

import com.bigdata.processor.handler.IJobHandler;
import com.bigdata.processor.handler.JobHandler;
import com.bigdata.processor.log.JobLogger;
import com.bigdata.processor.util.CommandUtil;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@JobHandler("dataAnalysisHandler")
public class DataProcessingJobHandler extends IJobHandler {
    
    @Override
    public int execute(String... params) throws IOException {
        if (params == null || params.length < 2) {
            JobLogger.log("Invalid parameters");
            return -1;
        }
        
        String dataset = params[0];
        String operation = params[1];
        String command = CommandUtil.buildCommand(dataset, operation);
        
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        String line;
        while ((line = reader.readLine()) != null) {
            JobLogger.log(line);
        }
        
        try {
            return process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -2;
        }
    }
}

// --- Util Class ---
package com.bigdata.processor.util;

import java.util.regex.Pattern;

public class CommandUtil {
    private static final Pattern INVALID_PATTERN = Pattern.compile("[&;|`\\\\$]|\$\\$");
    
    public static String buildCommand(String dataset, String operation) {
        String safeDataset = filterInput(dataset);
        String safeOperation = filterInput(operation);
        // 漏洞点：拼接前未正确处理参数边界
        return String.format("/opt/dataengine/process.sh %s %s", safeDataset, safeOperation);
    }
    
    private static String filterInput(String input) {
        if (input == null) return "";
        // 误导性过滤：仅移除部分特殊字符
        return input.replaceAll(INVALID_PATTERN.pattern(), "");
    }
}

// --- Framework Base Classes ---
package com.bigdata.processor.handler;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public interface IJobHandler {
    int execute(String... params) throws IOException;
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@interface JobHandler {
    String value();
}

// --- Logging Component ---
package com.bigdata.processor.log;

public class JobLogger {
    public static void log(String message) {
        System.out.println("[JOB-LOG] " + message);
    }
}