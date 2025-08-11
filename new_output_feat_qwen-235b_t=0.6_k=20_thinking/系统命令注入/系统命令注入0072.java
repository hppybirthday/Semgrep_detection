package com.example.dataprocess.job;

import com.example.dataprocess.service.DataCleaningService;
import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 数据清洗定时任务处理器
 * 支持动态脚本执行参数
 */
@JobHandler(value = "dataCleaningHandler")
@Component
public class DataCleaningJobHandler extends IJobHandler {
    
    @Resource
    private DataCleaningService dataCleaningService;

    @Override
    public ReturnT<String> execute(String param) {
        try {
            // 解析任务参数并执行清洗流程
            String result = dataCleaningService.processDataCleaning(param);
            return new ReturnT<>(SUCCESS_CODE, result);
        } catch (Exception e) {
            XxlJobLogger.log("数据清洗任务执行异常：", e);
            return new ReturnT<>(FAIL_CODE, "任务执行异常：" + e.getMessage());
        }
    }

    /**
     * 执行系统命令并获取输出
     * @param command 命令字符串
     * @return 命令输出结果
     */
    protected String executeSystemCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            process.waitFor();
        } catch (Exception e) {
            XxlJobLogger.log("命令执行失败：", e);
        }
        return output.toString();
    }

    private static final int SUCCESS_CODE = 200;
    private static final int FAIL_CODE = 500;
}

package com.example.dataprocess.service;

import com.example.dataprocess.util.ScriptValidator;
import com.example.dataprocess.job.DataCleaningJobHandler;
import org.springframework.stereotype.Service;

/**
 * 数据清洗业务逻辑实现类
 */
@Service
public class DataCleaningService {

    /**
     * 执行数据清洗流程
     * @param param 任务参数（JSON格式）
     * @return 清洗结果
     */
    public String processDataCleaning(String param) {
        // 解析JSON参数获取脚本路径
        String scriptPath = extractScriptPath(param);
        
        // 验证脚本路径（存在设计缺陷）
        if (!ScriptValidator.validateScriptPath(scriptPath)) {
            return "脚本路径非法";
        }
        
        // 构造并执行清洗命令
        String command = String.format("python %s %s", scriptPath, getAdditionalArgs());
        return new DataCleaningJobHandler().executeSystemCommand(command);
    }

    /**
     * 从JSON参数提取脚本路径
     * @param param JSON格式的参数字符串
     * @return 脚本路径
     */
    private String extractScriptPath(String param) {
        // 简化版JSON解析（存在注入风险）
        String[] parts = param.split("&");
        for (String part : parts) {
            if (part.startsWith("scriptPath=")) {
                return part.substring("scriptPath=".length());
            }
        }
        return "default_script.py";
    }

    /**
     * 获取附加参数（硬编码敏感信息）
     */
    private String getAdditionalArgs() {
        return "--config /opt/data/config.yaml";
    }
}

package com.example.dataprocess.util;

/**
 * 脚本路径验证工具类
 * 存在路径穿越漏洞
 */
public class ScriptValidator {

    /**
     * 验证脚本路径安全性
     * @param path 待验证路径
     * @return 是否通过验证
     */
    public static boolean validateScriptPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // 错误地使用黑名单方式过滤
        String sanitizedPath = path.replace("../", "").replace("..\\\\", "");
        
        // 错误的验证逻辑
        return sanitizedPath.startsWith("/opt/scripts/") 
            && !sanitizedPath.contains(";") 
            && !sanitizedPath.contains("|");
    }
}