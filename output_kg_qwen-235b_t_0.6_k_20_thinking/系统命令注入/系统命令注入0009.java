package com.bigdata.pipeline.handler;

import lombok.extern.slf4j.Slf4j;
import java.io.*;
import java.util.*;

/**
 * @Description: 数据处理管道抽象组件
 * @Author: security-expert
 */
@Slf4j
public abstract class DataPipelineHandler {
    public abstract ProcessResult executePipeline(DataContext context) throws Exception;

    protected String buildCommand(String baseCommand, Map<String, String> params) {
        StringBuilder cmd = new StringBuilder(baseCommand);
        params.forEach((key, value) -> cmd.append(" --").append(key).append(" ").append(value));
        return cmd.toString();
    }

    protected ProcessResult runCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        ProcessResult result = new ProcessResult();
        
        try (BufferedReader inputReader = new BufferedReader(
             new InputStreamReader(process.getInputStream()));
             BufferedReader errorReader = new BufferedReader(
             new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = inputReader.readLine()) != null) {
                result.getOutput().add(line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                result.getErrors().add(line);
            }
            
            result.setExitCode(process.waitFor());
        } catch (Exception e) {
            log.error("Command execution error: {}", e.getMessage());
            result.setExitCode(1);
        }
        
        return result;
    }
}

package com.bigdata.pipeline.handler.impl;

import com.bigdata.pipeline.handler.*;
import com.bigdata.pipeline.model.*;
import lombok.extern.slf4j.Slf4j;
import java.util.*;

/**
 * @Description: 数据清洗处理器（存在命令注入漏洞）
 */
@Slf4j
public class DataCleaningHandler extends DataPipelineHandler {
    @Override
    public ProcessResult executePipeline(DataContext context) throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("input", context.getInputPath());
        params.put("output", context.getOutputPath());
        params.put("cleanType", context.getCleanType());
        
        // 漏洞点：直接拼接用户输入到命令中
        String command = buildCommand("/opt/bigdata/cleaner.sh", params);
        log.info("Executing cleaning command: {}", command);
        
        return runCommand(command);
    }
}

package com.bigdata.pipeline.scheduler;

import com.bigdata.pipeline.handler.*;
import com.bigdata.pipeline.model.*;
import lombok.extern.slf4j.Slf4j;
import java.util.*;

/**
 * @Description: 管道调度器
 */
@Slf4j
public class PipelineScheduler {
    private final List<DataPipelineHandler> handlers = new ArrayList<>();

    public void registerHandler(DataPipelineHandler handler) {
        handlers.add(handler);
    }

    public ProcessResult scheduleJob(DataContext context) {
        return handlers.stream()
            .filter(handler -> handler.supports(context.getJobType()))
            .findFirst()
            .map(handler -> {
                try {
                    return handler.executePipeline(context);
                } catch (Exception e) {
                    log.error("Pipeline execution failed: {}", e.getMessage());
                    return new ProcessResult();
                }
            })
            .orElseGet(() -> {
                log.warn("No handler found for job type: {}", context.getJobType());
                return new ProcessResult();
            });
    }
}

package com.bigdata.pipeline.model;

import java.util.*;

/**
 * @Description: 数据处理上下文
 */
public class DataContext {
    private String jobType;
    private String inputPath;
    private String outputPath;
    private String cleanType;
    
    // Getters and setters
    public String getJobType() { return jobType; }
    public void setJobType(String jobType) { this.jobType = jobType; }
    
    public String getInputPath() { return inputPath; }
    public void setInputPath(String inputPath) { this.inputPath = inputPath; }
    
    public String getOutputPath() { return outputPath; }
    public void setOutputPath(String outputPath) { this.outputPath = outputPath; }
    
    public String getCleanType() { return cleanType; }
    public void setCleanType(String cleanType) { this.cleanType = cleanType; }
}

package com.bigdata.pipeline.model;

import java.util.*;

/**
 * @Description: 进程执行结果
 */
public class ProcessResult {
    private int exitCode;
    private List<String> output = new ArrayList<>();
    private List<String> errors = new ArrayList<>();
    
    // Getters and setters
    public int getExitCode() { return exitCode; }
    public void setExitCode(int exitCode) { this.exitCode = exitCode; }
    
    public List<String> getOutput() { return output; }
    public void setOutput(List<String> output) { this.output = output; }
    
    public List<String> getErrors() { return errors; }
    public void setErrors(List<String> errors) { this.errors = errors; }
}