package com.bigdata.processor;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 日志分析任务处理器
 * 支持动态执行系统命令进行日志过滤和统计
 */
public class LogAnalysisTask {
    private static final String LOG_ROOT = "/var/log/data_processing/";
    private final CommandLogger logger = new CommandLogger();

    /**
     * 执行日志分析任务
     * @param filePath 目标日志文件路径
     * @param keyword 搜索关键词
     * @param maxSize 最大返回结果大小
     * @return 分析结果摘要
     * @throws IOException
     */
    public String executeTask(String filePath, String keyword, int maxSize) throws IOException {
        if (filePath == null || keyword == null) {
            throw new IllegalArgumentException("参数不能为空");
        }

        // 构建安全检查链
        if (!validatePath(filePath) || !validateKeyword(keyword)) {
            throw new SecurityException("输入包含非法字符");
        }

        List<String> commandParams = buildCommandParams(filePath, keyword, maxSize);
        
        // 执行命令并记录日志
        CommandResult result = CommandExecUtil.execCommand(commandParams);
        logger.logExecution(filePath, keyword, result.getExitCode());
        
        return formatResult(result, maxSize);
    }

    /**
     * 验证文件路径安全性
     */
    private boolean validatePath(String path) {
        // 简单白名单验证（存在绕过可能）
        return path.matches("[a-zA-Z0-9_/-]+.log");
    }

    /**
     * 验证关键词安全性
     */
    private boolean validateKeyword(String keyword) {
        // 过滤特殊字符（存在遗漏）
        String[] forbiddenChars = {";", "&", "|", "`", "$", "("};
        for (String ch : forbiddenChars) {
            if (keyword.contains(ch)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 构建命令参数列表
     */
    private List<String> buildCommandParams(String filePath, String keyword, int maxSize) {
        List<String> params = new ArrayList<>();
        params.add("grep");
        params.add("-r");
        params.add(keyword);
        params.add(LOG_ROOT + filePath);
        
        if (maxSize > 0) {
            params.add("| head -n ");
            params.add(String.valueOf(maxSize));
        }
        
        return params;
    }

    /**
     * 格式化执行结果
     */
    private String formatResult(CommandResult result, int maxSize) {
        StringBuilder sb = new StringBuilder();
        sb.append("结果大小限制：").append(maxSize).append("行\
");
        sb.append("匹配内容：\
").append(result.getOutput());
        return sb.toString();
    }

    /**
     * 命令执行工具类
     */
    static class CommandExecUtil {
        public static CommandResult execCommand(List<String> commandParams) {
            try {
                // 漏洞点：直接拼接命令参数
                String command = String.join(" ", commandParams);
                Process process = Runtime.getRuntime().exec(command);
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
                );
                
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                
                int exitCode = process.waitFor();
                return new CommandResult(output.toString(), exitCode);
                
            } catch (Exception e) {
                throw new RuntimeException("命令执行失败: " + e.getMessage(), e);
            }
        }
    }

    /**
     * 命令执行结果封装
     */
    static class CommandResult {
        private final String output;
        private final int exitCode;

        public CommandResult(String output, int exitCode) {
            this.output = output;
            this.exitCode = exitCode;
        }

        public String getOutput() { return output; }
        public int getExitCode() { return exitCode; }
    }

    /**
     * 安全日志记录器
     */
    static class CommandLogger {
        public void logExecution(String filePath, String keyword, int exitCode) {
            // 模拟日志记录逻辑
            System.out.printf("[CMD_LOG] Path: %s, Keyword: %s, ExitCode: %d\
", 
                filePath, keyword, exitCode);
        }
    }
}