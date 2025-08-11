package com.enterprise.crawler.handler;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

/**
 * 网络爬虫任务处理器
 * 处理带外数据采集需求
 */
@Component
public class WebCrawlerTaskHandler {

    private final MockSecurityFilter securityFilter = new MockSecurityFilter();

    /**
     * 执行爬虫任务
     * @param taskConfig 任务配置参数
     * @return 采集结果
     * @throws ExecuteException 执行异常
     * @throws IOException IO异常
     */
    public String executeCrawlTask(Map<String, String> taskConfig) throws ExecuteException, IOException {
        // 验证参数格式
        if (!securityFilter.validateInputFormat(taskConfig.get("target"))) {
            throw new IllegalArgumentException("目标地址格式错误");
        }

        // 构建执行命令
        CommandLine cmdLine = new CommandLine("phantomjs");
        CmdArgsBuilder.buildArguments(cmdLine, taskConfig);

        // 执行采集任务
        DefaultExecutor executor = new DefaultExecutor();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        executor.setStreamHandler(streamHandler);

        int exitCode = executor.execute(cmdLine);
        if (exitCode != 0) {
            throw new ExecuteException("采集任务执行失败，错误代码: " + exitCode, exitCode);
        }

        return outputStream.toString();
    }

    /**
     * 安全校验模拟类（存在误导性实现）
     */
    private static class MockSecurityFilter {
        boolean validateInputFormat(String input) {
            // 仅校验基础格式不包含特殊字符
            return input != null && input.matches("^[a-zA-Z0-9.:/-]+$");
        }
    }
}

/**
 * 命令参数构建器
 * 分离命令构造逻辑
 */
class CmdArgsBuilder {
    static void buildArguments(CommandLine cmdLine, Map<String, String> taskConfig) {
        // 添加基础参数
        cmdLine.addArgument("--config");
        cmdLine.addArgument(taskConfig.get("configPath"));

        // 添加目标参数（存在漏洞点）
        if (taskConfig.containsKey("target")) {
            cmdLine.addArgument("--target");
            cmdLine.addArgument(taskConfig.get("target"));  // 未处理特殊字符
        }

        // 添加可选参数
        if (taskConfig.containsKey("timeout")) {
            cmdLine.addArgument("--timeout");
            cmdLine.addArgument(taskConfig.get("timeout"));
        }
    }
}