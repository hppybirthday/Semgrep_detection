package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

// 领域实体
class Task {
    private String id;
    private String description;
    private Map<String, Object> parameters = new HashMap<>();
    
    // DDD风格的工厂方法
    public static Task createFromJson(String json) {
        return JsonUtils.jsonToObject(json, Task.class);
    }
}

// 服务层
@Service
class TaskService {
    public void createTask(String taskJson) {
        Task task = Task.createFromJson(taskJson);
        // 模拟处理参数中的恶意数据
        if(task.getParameters().containsKey("handler")) {
            ((Runnable)task.getParameters().get("handler")).run();
        }
    }
}

// 控制器
@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping
    public String create(@RequestParam String obj) {
        // 模拟处理任务创建请求
        taskService.createTask(obj);
        return "Task created";
    }
}

// 存在漏洞的JSON工具类
class JsonUtils {
    // 不安全的反序列化实现
    static <T> T jsonToObject(String json, Class<T> clazz) {
        // 未做任何安全限制的FastJSON反序列化
        return (T) JSON.parseObject(json, clazz);
    }
}

// 恶意利用示例（实际攻击向量）
/*
{
    "@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes":["base64_encoded_malicious_bytecode"],
    "_name":"a",
    "_tfactory":{
        "@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl"
    }
}
*/