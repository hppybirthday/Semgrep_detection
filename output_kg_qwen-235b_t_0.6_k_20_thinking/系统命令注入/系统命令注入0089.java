package com.bigdata.pipeline.handler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 大数据预处理任务处理器
 * @author dataengineer 2024-05-20 15:30:00
 */
@JobHandler(value="dataPreprocessingHandler")
@Component
public class DataPreprocessingHandler extends IJobHandler {
    
    private static final String SCRIPT_PATH = "/opt/data/scripts/preprocess.sh";
    
    @Override
    public ReturnT<String> execute(String param) throws Exception {
        XxlJobLogger.log("开始执行数据预处理任务，参数：" + param);
        
        try {
            // 解析JSON参数 {"inputPath":"/data/input/","fileName":"test.csv"}
            String inputPath = parseJsonParam(param, "inputPath");
            String fileName = parseJsonParam(param, "fileName");
            
            // 构建处理命令
            List<String> command = new ArrayList<>();
            command.add("sh");
            command.add("-c");
            command.add(SCRIPT_PATH + " " + inputPath + " " + fileName);
            
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            
            // 读取执行日志
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                XxlJobLogger.log("处理日志：" + line);
            }
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                return SUCCESS;
            } else {
                return new ReturnT<>(FAIL.getCode(), "处理失败，退出码：" + exitCode);
            }
            
        } catch (Exception e) {
            XxlJobLogger.log("处理异常：", e);
            return new ReturnT<>(FAIL.getCode(), "执行异常：" + e.getMessage());
        }
    }
    
    /**
     * 简单的JSON参数解析（实际应使用JSON库）
     */
    private String parseJsonParam(String json, String key) {
        // 模拟JSON解析逻辑
        String target = "\\"" + key + "\\":\\"";
        int startIndex = json.indexOf(target) + target.length();
        int endIndex = json.indexOf("\\"", startIndex);
        return json.substring(startIndex, endIndex);
    }
}