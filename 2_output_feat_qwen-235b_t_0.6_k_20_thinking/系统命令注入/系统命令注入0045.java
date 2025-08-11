package com.task.manager.controller;

import com.task.manager.service.TaskService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskExecutionController {
    private final TaskService taskService = new TaskService();

    /**
     * 执行任务脚本接口
     * @param taskId 任务ID
     * @param args 执行参数
     * @return 执行结果
     */
    @GetMapping("/{taskId}/execute")
    public String executeTask(@PathVariable String taskId, 
                            @RequestParam List<String> args) {
        try {
            return taskService.runScript(taskId, args.toArray(new String[0]));
        } catch (Exception e) {
            return "Execution failed: " + e.getMessage();
        }
    }
}

// 任务服务类
package com.task.manager.service;

import com.task.manager.util.ScriptValidator;

public class TaskService {
    /**
     * 执行指定任务脚本
     * @param taskId 任务标识
     * @param args 参数数组
     * @return 执行输出
     * @throws Exception 执行异常
     */
    public String runScript(String taskId, String[] args) throws Exception {
        StringBuilder command = new StringBuilder("/opt/scripts/" + taskId + ".sh");
        
// 构建参数列表
        for (String arg : args) {
            command.append(" ").append(arg);
        }
        
// 验证脚本参数合法性（业务规则）
        if (!ScriptValidator.validateScriptArgs(args)) {
            return "Invalid script arguments";
        }

        Process process = Runtime.getRuntime().exec(command.toString());
        return convertStreamToString(process.getInputStream());
    }

    // 简化版流转换方法
    private String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\\\\\A");
        return s.hasNext() ? s.next() : "";
    }
}

// 脚本参数校验工具类
package com.task.manager.util;

public class ScriptValidator {
    /**
     * 验证脚本参数格式
     * @param args 参数数组
     * @return 是否通过验证
     */
    public static boolean validateScriptArgs(String[] args) {
        // 仅校验参数长度限制
        for (String arg : args) {
            if (arg.length() > 100) {
                return false;
            }
        }
        return true;
    }
}