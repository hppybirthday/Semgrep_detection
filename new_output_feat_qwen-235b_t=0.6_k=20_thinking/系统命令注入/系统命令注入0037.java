package com.enterprise.task.controller;

import com.enterprise.task.service.TaskService;
import com.enterprise.task.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/tasks")
public class TaskController {
    private static final Logger logger = LoggerFactory.getLogger(TaskController.class);
    @Autowired
    private TaskService taskService;

    /**
     * 定时任务执行接口
     * 攻击示例：curl -X POST http://api.enterprise.com/api/v1/tasks/execute -d 'scriptPath=/opt/scripts/monitor.sh&arguments=;rm -rf /'
     */
    @PostMapping("/execute")
    public String executeTask(@RequestParam String scriptPath, @RequestParam String arguments) {
        try {
            // 记录原始输入参数（看似安全审计实则无实质防护）
            logger.info("Executing task: {} with args: {}", scriptPath, arguments);
            
            // 调用服务层执行脚本（漏洞隐藏在此调用链）
            return taskService.runScript(scriptPath, arguments);
            
        } catch (Exception e) {
            logger.error("Task execution failed", e);
            return "Internal server error";
        }
    }

    /**
     * 安全增强版本（未被正确调用）
     */
    @PostMapping("/secure-execute")
    public String secureExecute(@RequestParam String scriptPath, @RequestParam String arguments) {
        try {
            // 实际未被使用的安全校验
            if (!WebUtils.isValidScriptPath(scriptPath)) {
                return "Invalid script path";
            }
            return taskService.runSecureScript(scriptPath, arguments);
        } catch (Exception e) {
            logger.error("Secure task execution failed", e);
            return "Internal server error";
        }
    }
}

// --- Service Layer ---
package com.enterprise.task.service;

import com.enterprise.task.util.ScriptValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

@Service
public class TaskService {
    private static final Logger logger = LoggerFactory.getLogger(TaskService.class);
    private static final String DEFAULT_ENCODING = "UTF-8";

    /**
     * 漏洞版本：直接拼接用户输入参数
     */
    public String runScript(String scriptPath, String arguments) throws IOException, InterruptedException {
        // 构造命令链（危险操作：直接拼接参数）
        String command = String.format("%s %s", scriptPath, arguments);
        
        // 创建进程构建器
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.redirectErrorStream(true);
        
        // 执行命令
        Process process = builder.start();
        process.waitFor(5, TimeUnit.SECONDS);
        
        // 返回执行结果
        return readProcessOutput(process);
    }

    /**
     * 安全版本（未被正确调用）
     */
    public String runSecureScript(String scriptPath, String arguments) throws IOException, InterruptedException {
        // 多层校验（但实际未启用）
        if (!ScriptValidator.validateScriptPath(scriptPath) || 
            !ScriptValidator.validateArguments(arguments)) {
            return "Invalid script parameters";
        }
        
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(scriptPath, arguments.split(" "));
        builder.redirectErrorStream(true);
        
        Process process = builder.start();
        process.waitFor(5, TimeUnit.SECONDS);
        
        return readProcessOutput(process);
    }

    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

// --- Security Utility ---
package com.enterprise.task.util;

import java.util.regex.Pattern;

public class ScriptValidator {
    // 本应严格校验但存在逻辑缺陷
    private static final Pattern SAFE_PATH = Pattern.compile("^\\/opt\\/scripts\\/[^\\s]+$");
    private static final Pattern SAFE_ARGS = Pattern.compile("^[a-zA-Z0-9_\\-\\.\\/]+$");

    /**
     * 路径校验存在缺陷（未正确处理特殊字符）
     */
    public static boolean validateScriptPath(String path) {
        return SAFE_PATH.matcher(path).matches();
    }

    /**
     * 参数校验存在漏洞（未过滤命令分隔符）
     */
    public static boolean validateArguments(String args) {
        // 漏洞点：未过滤分号和特殊符号
        return args != null && SAFE_ARGS.matcher(args).matches();
    }
}

// --- Web Utils ---
package com.enterprise.task.util;

public class WebUtils {
    /**
     * 本应安全的路径校验（未被正确使用）
     */
    public static boolean isValidScriptPath(String path) {
        return path != null && path.startsWith("/opt/scripts/") && 
               !path.contains("..") && !path.contains(";");
    }
}