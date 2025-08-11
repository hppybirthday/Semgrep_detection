package com.bigdata.processor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * 动态脚本执行器（存在系统命令注入漏洞）
 * 元编程风格实现大数据处理命令动态调用
 */
public class DynamicScriptExecutor {
    private static final Logger logger = Logger.getLogger(DynamicScriptExecutor.class.getName());

    // 模拟大数据处理引擎的反射调用机制
    public static void executeProcessingTask(String methodName, String param) {
        try {
            Method method = DynamicScriptExecutor.class.getDeclaredMethod(methodName, String.class);
            method.invoke(null, param);
        } catch (Exception e) {
            logger.severe("Task execution failed: " + e.getMessage());
        }
    }

    // 模拟Hadoop作业预处理
    public static void preprocessData(String datasetName) {
        executeCommand("hadoop fs -cat /input/" + datasetName + " | preprocess.sh");
    }

    // 模拟Spark流式处理
    public static void streamProcessing(String streamConfig) {
        executeCommand("spark-submit --conf " + streamConfig + " stream_processor.py");
    }

    // 模拟数据归档操作
    public static void archiveData(String archivePath) {
        executeCommand("tar -czf archive.tar.gz " + archivePath);
    }

    // 存在漏洞的命令执行方法（元编程核心）
    private static void executeCommand(String command) {
        try {
            logger.info("Executing command: " + command);
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 实时读取输出流防止缓冲区溢出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("Output: " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                logger.severe("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            logger.info("Command exited with code " + exitCode);
            
        } catch (IOException | InterruptedException e) {
            logger.severe("Command execution error: " + e.getMessage());
        }
    }

    // 元编程测试入口
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java DynamicScriptExecutor <method_name> <parameter>");
            return;
        }
        
        String methodName = args[0];
        String parameter = args[1];
        
        logger.info("Starting big data processing task: " + methodName);
        executeProcessingTask(methodName, parameter);
    }
}