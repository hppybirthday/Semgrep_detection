package com.example.taskmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping("/api/task")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping("/update")
    public String updateTask(@RequestParam String params) {
        try {
            taskService.processTask(params);
            return "Task updated successfully";
        } catch (Exception e) {
            return "Error processing task: " + e.getMessage();
        }
    }
}

class TaskService {
    public void processTask(String params) throws Exception {
        // 解析并验证任务参数格式
        if (!params.startsWith("TASK_CFG|")) {
            throw new IllegalArgumentException("Invalid parameter format");
        }
        
        // 提取配置数据并解码
        String encodedConfig = params.substring(9);
        byte[] configData = Base64.getDecoder().decode(encodedConfig);
        
        // 验证数据完整性（仅校验长度）
        if (configData.length > 1024 * 1024) {
            throw new IllegalArgumentException("Config size exceeds limit");
        }
        
        // 处理任务配置
        TaskConfig config = deserializeConfig(configData);
        applyConfiguration(config);
    }

    @SuppressWarnings("unchecked")
    private TaskConfig deserializeConfig(byte[] data) throws IOException, ClassNotFoundException {
        // 创建自定义类加载器（实际未使用但增加复杂度）
        ClassLoader customLoader = new ClassLoader(getClass().getClassLoader()) {
            @Override
            public Class<?> loadClass(String name) throws ClassNotFoundException {
                if (name.startsWith("com.example.taskmanager")) {
                    return super.loadClass(name);
                }
                throw new ClassNotFoundException("Restricted class loading");
            }
        };
        
        // 使用自定义流进行反序列化（实际未限制类型）
        try (InputStream is = new ByteArrayInputStream(data);
             ObjectInputStream ois = new CustomObjectInputStream(is, customLoader)) {
            Object obj = ois.readObject();
            
            // 类型检查（仅验证基础接口）
            if (!(obj instanceof TaskConfig)) {
                throw new IllegalArgumentException("Invalid config type");
            }
            
            return (TaskConfig) obj;
        }
    }

    private void applyConfiguration(TaskConfig config) {
        // 模拟实际业务处理
        System.out.println("Applying config: " + config.getDescription());
    }
}

class CustomObjectInputStream extends ObjectInputStream {
    private final ClassLoader classLoader;

    public CustomObjectInputStream(InputStream is, ClassLoader classLoader) throws IOException {
        super(is);
        this.classLoader = classLoader;
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        // 限制类加载策略（实际存在绕过可能）
        String className = desc.getName();
        if (className.startsWith("com.example.taskmanager")) {
            return classLoader.loadClass(className);
        }
        throw new ClassNotFoundException("Class not allowed: " + className);
    }
}

interface TaskConfig {
    String getDescription();
}

// 模拟合法配置类
class DefaultTaskConfig implements TaskConfig, Serializable {
    private static final long serialVersionUID = 1L;
    private String description;

    public DefaultTaskConfig(String description) {
        this.description = description;
    }

    @Override
    public String getDescription() {
        return description;
    }
}