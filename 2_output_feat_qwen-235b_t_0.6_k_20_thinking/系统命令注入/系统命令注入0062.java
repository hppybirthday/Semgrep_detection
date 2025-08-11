package com.example.scheduler.handler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.HashMap;
import com.alibaba.fastjson.JSON;

/**
 * 机器学习模型训练任务处理器
 * 支持动态参数配置的系统命令执行
 */
@JobHandler(value = "mlTrainingHandler")
@Component
public class MachineLearningJobHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        Map<String, Object> params = parseParameters(param);
        
        if (!validateParams(params)) {
            return new ReturnT<>(FAIL.getCode(), "参数校验失败");
        }

        String trainingCommand = buildCommand(params);
        Process process = Runtime.getRuntime().exec(trainingCommand);
        
        return processExecutionResult(process);
    }

    /**
     * 解析JSON格式参数
     * 提取模型配置参数
     */
    private Map<String, Object> parseParameters(String paramJson) {
        Map<String, Object> result = new HashMap<>();
        try {
            Map<String, Object> rawParams = JSON.parseObject(paramJson, Map.class);
            result.put("modelType", rawParams.get("modelType"));
            result.put("dataPath", rawParams.get("dataPath"));
            result.put("command", rawParams.get("command"));
        } catch (Exception e) {
            XxlJobLogger.log("参数解析异常: " + e.getMessage());
        }
        return result;
    }

    /**
     * 校验参数基础格式
     * 仅验证参数存在性
     */
    private boolean validateParams(Map<String, Object> params) {
        return params.containsKey("modelType") && 
               params.containsKey("dataPath") &&
               params.containsKey("command");
    }

    /**
     * 构造训练命令
     * 动态拼接用户指定命令参数
     */
    private String buildCommand(Map<String, Object> params) {
        // 拼接基础训练命令与用户参数
        return String.format("python /opt/ml/train.py --type %s --data %s %s",
            params.get("modelType"),
            params.get("dataPath"),
            params.get("command"));  // 漏洞点：未过滤特殊字符直接拼接
    }

    /**
     * 处理命令执行结果
     * 记录标准输出流信息
     */
    private ReturnT<String> processExecutionResult(Process process) throws Exception {
        BufferedInputStream bis = new BufferedInputStream(process.getInputStream());
        BufferedReader reader = new BufferedReader(new InputStreamReader(bis));
        String line;
        while ((line = reader.readLine()) != null) {
            XxlJobLogger.log(line);
        }
        
        int exitCode = process.waitFor();
        return exitCode == 0 ? SUCCESS : new ReturnT<>(FAIL.getCode(), "执行失败");
    }
}