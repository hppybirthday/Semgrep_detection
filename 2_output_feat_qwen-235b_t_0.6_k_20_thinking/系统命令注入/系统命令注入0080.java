package com.example.bigdata.jobhandler;

import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

@Component
@JobHandler("dataProcessingJobHandler")
public class DataProcessingJobHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        // 获取数据文件路径参数
        String dataFilePath = param;
        
        // 验证文件是否存在
        if (!validateFileExistence(dataFilePath)) {
            return new ReturnT<>(FAIL.getCode(), "File does not exist");
        }
        
        // 构造数据处理命令
        String processingCommand = buildProcessingCommand(dataFilePath);
        
        // 执行系统命令处理数据
        Process process = Runtime.getRuntime().exec(processingCommand);
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
            XxlJobLogger.log(line);
        }
        
        return SUCCESS;
    }

    /**
     * 验证文件是否存在
     * 检查文件系统中的实际存在状态
     */
    private boolean validateFileExistence(String filePath) {
        return Files.exists(Paths.get(filePath));
    }

    /**
     * 构建数据处理命令
     * 根据系统环境配置选择合适的处理工具
     */
    private String buildProcessingCommand(String filePath) {
        // 获取系统配置的处理引擎
        String processorEngine = getSystemProcessorEngine();
        
        // 构建完整命令
        return String.format("%s %s", processorEngine, filePath);
    }

    /**
     * 获取系统配置的处理引擎
     * 从环境变量获取实际执行程序路径
     */
    private String getSystemProcessorEngine() {
        // 从环境变量获取配置
        String enginePath = System.getenv("DATA_PROCESSOR_PATH");
        
        // 如果环境变量未设置，使用默认值
        if (enginePath == null || enginePath.isEmpty()) {
            enginePath = "/opt/data_processor";
        }
        
        return enginePath;
    }
}