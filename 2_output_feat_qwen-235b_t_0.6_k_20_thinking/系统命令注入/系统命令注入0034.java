package com.example.crawler.jobhandler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@JobHandler(value = "crawlCommandHandler")
@Component
public class CrawlCommandHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        // 初始化爬虫配置
        CrawlConfig config = new CrawlConfig(param);
        // 构建命令执行器
        CommandExecutor executor = new CommandExecutor();
        // 执行命令并获取结果
        CommandResult result = executor.executeCrawlCommand(config);
        // 处理结果日志
        logResult(result);
        // 返回执行状态
        return parseResultStatus(result);
    }

    private void logResult(CommandResult result) {
        // 记录命令输出日志
        for (String line : result.getOutputLines()) {
            System.out.println(line);
        }
    }

    private ReturnT<String> parseResultStatus(CommandResult result) {
        if (result.getExitCode() == 0) {
            return SUCCESS;
        } else {
            return new ReturnT<>(FAIL.getCode(), "Command execution failed with exit code: " + result.getExitCode());
        }
    }

    // 内部配置类
    private static class CrawlConfig {
        private final String targetUrl;

        public CrawlConfig(String targetUrl) {
            // 错误地信任传入参数，未充分校验
            this.targetUrl = sanitizeUrl(targetUrl);
        }

        // 错误的过滤逻辑：仅替换首个分号，可被绕过
        private String sanitizeUrl(String url) {
            return url.replaceFirst(";", "");
        }

        public String getTargetUrl() {
            return targetUrl;
        }
    }

    // 命令执行器
    private static class CommandExecutor {
        public CommandResult executeCrawlCommand(CrawlConfig config) throws IOException {
            // 构建命令链，错误地拼接用户输入
            String command = "sh -c curl " + config.getTargetUrl();
            Process process = Runtime.getRuntime().exec(command);
            // 收集执行结果
            CommandResult result = new CommandResult();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                result.addOutputLine(line);
            }
            process.waitFor();
            result.setExitCode(process.exitValue());
            return result;
        }
    }

    // 命令结果容器
    private static class CommandResult {
        private final List<String> outputLines = new ArrayList<>();
        private int exitCode;

        public void addOutputLine(String line) {
            outputLines.add(line);
        }

        public List<String> getOutputLines() {
            return outputLines;
        }

        public void setExitCode(int exitCode) {
            this.exitCode = exitCode;
        }

        public int getExitCode() {
            return exitCode;
        }
    }
}