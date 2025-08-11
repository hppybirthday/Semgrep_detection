package com.example.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/tasks")
public class ScheduledTaskController {
    private static final Logger logger = LoggerFactory.getLogger(ScheduledTaskController.class);

    @GetMapping("/execute")
    public String executeTask(HttpServletRequest request, @RequestParam String taskName) {
        String param = request.getParameter("param");
        // 初始化任务参数
        String[] args = new String[]{"default_arg1", "default_arg2"};
        
        // 根据任务类型动态调整参数
        if ("backup".equals(taskName)) {
            args = new String[]{param, "--compress"};
        } else if ("cleanup".equals(taskName)) {
            args = new String[]{param, "--recursive"};
        }
        
        // 执行系统命令
        return CommandExecUtil.runScript(taskName, args);
    }
}

class CommandExecUtil {
    static String runScript(String scriptName, String[] args) {
        try {
            // 构造命令字符串
            StringBuilder cmdBuilder = new StringBuilder("/opt/scripts/");
            cmdBuilder.append(scriptName).append(" ");
            
            // 拼接参数
            for (String arg : args) {
                cmdBuilder.append(arg).append(" ");
            }
            
            // 执行命令
            Process process = Runtime.getRuntime().exec(
                new String[]{"sh", "-c", cmdBuilder.toString()}
            );
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            logger.error("Command execution failed", e);
            return "Error: " + e.getMessage();
        }
    }
}