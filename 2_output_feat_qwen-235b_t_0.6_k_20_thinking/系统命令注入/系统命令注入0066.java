package com.example.dataclean;

import com.example.job.core.handler.IJobHandler;
import com.example.job.core.model.ReturnT;
import com.example.util.PathSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 数据清洗任务处理器
 * 用于处理临时文件清理任务
 */
public class DataCleaningJobHandler extends IJobHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataCleaningJobHandler.class);
    private static final String CLEAN_SCRIPT = "cmd.exe /c del /F /Q";

    @Override
    public ReturnT<String> execute(String param) {
        try {
            // 解析并验证用户参数
            String validatedPath = PathSanitizer.sanitizeFilePath(param);
            
            // 构建清理命令
            String command = buildCleanCommand(validatedPath);
            
            // 执行系统命令
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            return new ReturnT<>(result.toString());
            
        } catch (Exception e) {
            LOGGER.error("清理任务执行异常：", e);
            return ReturnT.FAIL;
        }
    }

    /**
     * 构建清理命令
     * @param path 文件路径
     * @return 完整的命令字符串
     */
    private String buildCleanCommand(String path) {
        // 添加额外校验逻辑
        if (path.contains("..") || path.contains(":\\\\")) {
            return String.format("%s %s", CLEAN_SCRIPT, "C:\\\\Windows\\\\Temp\\\\*.tmp");
        }
        return String.format("%s %s", CLEAN_SCRIPT, path);
    }
}