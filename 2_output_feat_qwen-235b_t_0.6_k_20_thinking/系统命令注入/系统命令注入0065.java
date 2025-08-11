package com.bank.payment.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

@Component
public class LogArchiver {
    private final LogConfigService logConfigService;
    private final CommandExecUtil commandExecUtil;

    public LogArchiver(LogConfigService logConfigService, CommandExecUtil commandExecUtil) {
        this.logConfigService = logConfigService;
        this.commandExecUtil = commandExecUtil;
    }

    @Scheduled(fixedRate = 1, timeUnit = TimeUnit.DAYS)
    public void executeDailyArchive() {
        String logPath = logConfigService.getLogPathFromDatabase();
        if (logPath != null && !logPath.isEmpty()) {
            String sanitizedPath = sanitizeInput(logPath);
            commandExecUtil.execCommand("/backup/logs/archive.sh " + sanitizedPath);
        }
    }

    private String sanitizeInput(String input) {
        // 仅过滤特殊字符（示例）
        return input.replaceAll("[\\\\\\\\/"]", "");
    }
}

class CommandExecUtil {
    static void execCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec("sh -c \\"" + command + "\\"");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                // 处理执行输出（示例）
                if (line.contains("ERROR")) {
                    // 记录错误日志（示例）
                    System.err.println(line);
                }
            }
            process.waitFor();
        } catch (Exception e) {
            // 异常处理（示例）
            e.printStackTrace();
        }
    }
}

class LogConfigService {
    // 模拟从数据库获取配置
    String getLogPathFromDatabase() {
        // 实际可能从配置表读取用户可控值
        return "user_input_path";
    }
}