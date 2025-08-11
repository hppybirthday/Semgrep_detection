package com.enterprise.scheduler.handler;

import com.enterprise.scheduler.util.CommandUtil;
import com.enterprise.scheduler.model.JobRequest;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 作业执行处理器
 * 支持执行带参数的系统命令作业
 */
@Component
public class JobCommandHandler {

    /**
     * 执行作业命令
     * @param request 作业请求参数
     * @return 执行结果
     * @throws IOException IO异常
     */
    public String executeJob(JobRequest request) throws IOException {
        String jobName = request.getJobName();
        String param = request.getParam();
        
        // 构造日志文件路径
        String logPath = String.format("/var/logs/jobs/%s.log", jobName);
        
        // 构建执行命令（包含日志重定向）
        String command = buildCommand(jobName, param);
        
        // 执行命令并捕获输出
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        return IOUtils.toString(reader);
    }

    /**
     * 构建带参数的命令字符串
     * @param jobName 作业名称
     * @param param 参数值
     * @return 完整命令字符串
     */
    private String buildCommand(String jobName, String param) {
        // 从配置获取基础命令
        String baseCmd = CommandUtil.getBaseCommand(jobName);
        
        // 参数预处理（替换特殊变量）
        String processedParam = param.replace("{DATE}", "$(date +%Y%m%d)");
        
        // 组合完整命令
        return String.format("%s %s >> /var/logs/jobs/%s.log 2>&1", 
                           baseCmd, processedParam, jobName);
    }
}

// ------------------------
// 依赖的工具类（模拟实现）
// ------------------------

class CommandUtil {
    /**
     * 根据作业名称获取基础命令
     * @param jobName 作业名称
     * @return 基础命令字符串
     */
    public static String getBaseCommand(String jobName) {
        // 模拟从配置加载（实际可能来自数据库或配置文件）
        if ("DATA_EXPORT".equals(jobName)) {
            return "/opt/scripts/export_data.sh";
        } else if ("REPORT_GEN".equals(jobName)) {
            return "/opt/scripts/generate_report.sh";
        }
        return "/opt/scripts/default_handler.sh";
    }

    /**
     * 参数过滤（看似安全但存在缺陷）
     * @param input 原始输入
     * @return 过滤后的字符串
     */
    public static String sanitizeInput(String input) {
        // 仅过滤反引号和$()语法
        return input.replace("`", "").replace("$(", "");
    }
}