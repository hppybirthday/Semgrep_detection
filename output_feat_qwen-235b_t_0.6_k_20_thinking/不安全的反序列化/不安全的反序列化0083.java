package com.example.taskmanager;

import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.concurrent.TimeUnit;

// 模拟任务实体类
class Task implements Serializable {
    private String taskId;
    private String taskName;
    private String payload; // 模拟存储敏感数据字段

    // 快速生成getter/setter
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    public String getTaskName() { return taskName; }
    public void setTaskName(String taskName) { this.taskName = taskName; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
}

// 任务服务类
@Service
class TaskService {
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // 从Redis恢复任务（存在漏洞的关键点）
    public Task restoreTaskFromCache(String taskId) {
        String taskJson = redisTemplate.opsForValue().get("task_cache:" + taskId);
        if (taskJson != null) {
            // 漏洞点：直接反序列化不可信数据
            return JSONObject.parseObject(taskJson, Task.class);
        }
        return null;
    }

    // 模拟任务处理逻辑
    public String processTask(Task task) {
        // 模拟执行任务时调用payload（放大攻击效果）
        return "Executing task: " + task.getTaskName() + ", Payload: " + task.getPayload();
    }
}

// 控制器层
@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskService taskService;

    // 模拟攻击者可控制的接口入口
    @PostMapping("/restore")
    public String restoreTask(@RequestParam String taskId) {
        Task task = taskService.restoreTaskFromCache(taskId);
        if (task != null) {
            return taskService.processTask(task);
        }
        return "Task not found";
    }
}

// 漏洞利用示例说明：
// 攻击者通过Redis注入恶意JSON：
// {"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
//  "_bytecodes":["base64_encoded_payload"],"_name":"a","_tfactory":{}}