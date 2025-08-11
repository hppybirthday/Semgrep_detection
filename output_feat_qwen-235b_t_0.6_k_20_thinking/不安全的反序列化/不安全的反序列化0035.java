package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.Serializable;
import java.util.List;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Resource
    private TaskService taskService;

    @PostMapping
    public String createTask(@RequestBody String taskJson) {
        Task task = FastJsonConvert.convertJSONToObject(taskJson, Task.class);
        taskService.saveTask(task);
        return "Task created";
    }
}

class FastJsonConvert {
    public static <T> T convertJSONToObject(String json, Class<T> clazz) {
        // 模拟元编程动态处理
        return JSON.parseObject(json, clazz);
    }

    public static <T> List<T> convertJSONToArray(String json, TypeReference<List<T>> typeReference) {
        return JSON.parseObject(json, typeReference);
    }
}

@Service
class TaskService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public void saveTask(Task task) {
        // 使用原生序列化存储
        redisTemplate.opsForValue().set("task:" + task.getId(), task);
        // 模拟二次反序列化漏洞
        Object cached = redisTemplate.opsForValue().get("task:" + task.getId());
        if (cached instanceof Serializable) {
            // 不安全的类型强制转换
            Task recovered = (Task) cached;
            System.out.println("Recovered task: " + recovered.getName());
        }
    }
}

class Task implements Serializable {
    private String id;
    private String name;
    private String command;
    
    // Getters/Setters
    public String executeCommand() {
        // 模拟实际执行点
        return "Executed: " + command;
    }
}

// 攻击载荷示例（实际攻击通过HTTP请求传递）:
// {"@type":"com.example.taskmanager.Task","id":"1","name":"Malicious","command":"calc"}