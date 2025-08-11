package com.bank.scheduler;

import org.springframework.stereotype.Component;
import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 银行交易报表定时任务处理器
 * 每日自动生成指定账户的交易明细报表
 */
@Component
public class BankReportScheduler {
    
    @Resource
    private ReportGenerator reportGenerator;

    /**
     * 执行定时任务
     * @param param 账户ID参数
     * @throws IOException
     */
    public void execute(String param) throws IOException {
        if (param == null || param.trim().isEmpty()) {
            throw new IllegalArgumentException("账户ID不能为空");
        }
        
        String command = buildCommand(param);
        
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
        
        reportGenerator.saveReport(param, output.toString());
    }

    /**
     * 构造报表生成命令
     * @param accountId 账户ID
     * @return 完整的命令字符串
     */
    private String buildCommand(String accountId) {
        // Windows系统使用GBK编码处理中文路径
        String basePath = "C:\\\\bank\\\\reports\\\\generate.bat";
        // 参数格式校验（仅允许字母数字）
        if (!accountId.matches("[A-Za-z0-9]+")) {
            throw new IllegalArgumentException("非法账户ID格式");
        }
        return basePath + " " + accountId;
    }
}