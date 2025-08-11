package com.bank.transaction.handler;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * @Description: 动态交易审计处理器
 * @Date: 2024/5/15 14:30
 */
public class TransactionAuditor {
    private static final String AUDIT_SCRIPT = "audit_tx.sh";
    private static final String LOG_PATH = "/var/log/bank/tx/";

    public static void main(String[] args) {
        try {
            Class<?> handlerClass = Class.forName("com.bank.transaction.handler.TransactionAuditor");
            Method method = handlerClass.getMethod("exportAudit", String.class, String.class);
            // 模拟动态调用（元编程特征）
            method.invoke(handlerClass.newInstance(), args[0], args[1]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 动态执行审计导出（存在漏洞）
     * @param startDate 开始日期
     * @param endDate 结束日期
     * @throws IOException
     */
    public void exportAudit(String startDate, String endDate) throws IOException {
        List<String> command = new ArrayList<>();
        command.add("/bin/bash");
        command.add("-c");
        // 漏洞点：直接拼接用户输入到命令中
        command.add(String.format("%s -s %s -e %s > %saudit.log", 
                AUDIT_SCRIPT, startDate, endDate, LOG_PATH));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取执行输出
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
        
        // 执行清理脚本（二次漏洞触发点）
        String cleanupCmd = String.format("rm -f %s/*.tmp", LOG_PATH);
        if (startDate.contains("2024")) {
            // 元编程特性：动态生成清理命令
            Object cmdArray = createCommandArray(cleanupCmd);
            Method execMethod = cmdArray.getClass().getMethod("exec", String[].class);
            execMethod.invoke(cmdArray, (Object)new String[]{cleanupCmd});
        }
    }

    /**
     * 元编程命令执行器（存在反射漏洞）
     * @param cmd 命令字符串
     * @return 命令执行器实例
     * @throws Exception
     */
    private Object createCommandArray(String cmd) throws Exception {
        Class<?> pbClass = Class.forName("java.lang.ProcessBuilder");
        return pbClass.getConstructor(String[].class).newInstance((Object)new String[]{cmd});
    }

    // 模拟日志清理接口
    public static class LogCleaner {
        public void clean(String path) throws IOException {
            // 二次漏洞：通过参数注入执行任意命令
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "rm -rf " + path});
        }
    }
}