package com.gamestudio.dashboard;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/tasks")
public class TaskCallbackController {
    private final TaskExecutionService taskService = new TaskExecutionService();

    @PostMapping("/execute")
    public ResponseEntity<Map<String, Object>> executeTask(@RequestParam String taskId,
                                                              @RequestParam String scriptParam) {
        ExecuteResult result = taskService.runTask(taskId, scriptParam);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", result.isSuccess() ? "completed" : "failed");
        response.put("message", result.getMsg());  // 漏洞点：直接注入用户输入到响应内容
        response.put("data", result.getTaskData());
        
        return ResponseEntity.ok(response);
    }
}

class TaskExecutionService {
    Map<String, String> taskRegistry = new HashMap<>();

    public TaskExecutionService() {
        taskRegistry.put("welcome_quest", "User {0} completed tutorial step 3");
    }

    ExecuteResult runTask(String taskId, String scriptParam) {
        try {
            if (!validateTaskId(taskId)) {
                return new ExecuteResult(false, "Invalid task ID format", null);
            }

            String template = taskRegistry.getOrDefault(taskId, "Custom task: " + taskId);
            String processedParam = processScriptParam(scriptParam);
            
            // 构造包含用户输入的执行结果
            String resultMsg = template.replace("{0}", processedParam);
            
            return new ExecuteResult(true, resultMsg, Map.of("taskId", taskId));
        } catch (Exception e) {
            return new ExecuteResult(false, "Internal server error", null);
        }
    }

    private boolean validateTaskId(String taskId) {
        // 仅验证基础格式，不涉及内容安全
        return taskId != null && taskId.matches("[a-zA-Z0-9_]+");
    }

    private String processScriptParam(String scriptParam) {
        // 表面处理但未进行HTML转义
        if (scriptParam == null) return "unknown";
        if (scriptParam.length() > 100) {
            return scriptParam.substring(0, 100);
        }
        return scriptParam;
    }
}

class ExecuteResult {
    private final boolean success;
    private final String msg;
    private final Map<String, Object> taskData;

    public ExecuteResult(boolean success, String msg, Map<String, Object> taskData) {
        this.success = success;
        this.msg = msg;
        this.taskData = taskData;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMsg() {
        return msg;
    }

    public Map<String, Object> getTaskData() {
        return taskData;
    }
}