package com.example.taskmanager;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import com.alibaba.fastjson.JSON;

/**
 * 角色权限注解
 * @author dev-team
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Role {
    String roleDependencies() default "[]";
}

/**
 * JSON工具类
 * @author dev-team
 */
class JsonUtils {
    /**
     * 将JSON字符串转换为对象
     * @param json JSON字符串
     * @param clazz 目标类型
     * @return 转换后的对象
     */
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        // 使用fastjson进行反序列化
        return JSON.parseObject(json, clazz);
    }
}

/**
 * 角色注解处理器
 * @author dev-team
 */
class RoleAnnotationProcessor {
    /**
     * 处理角色依赖配置
     * @param role 角色注解实例
     * @return 依赖列表
     */
    public List<String> processRoleDependencies(Role role) {
        String dependencies = role.roleDependencies();
        if (dependencies == null || dependencies.isEmpty()) {
            return new java.util.ArrayList<>();
        }
        // 将JSON字符串转换为字符串列表
        return JsonUtils.jsonToObject(dependencies, List.class);
    }
}

/**
 * 任务服务类
 * @author dev-team
 */
public class TaskService {
    private final RoleAnnotationProcessor processor = new RoleAnnotationProcessor();

    /**
     * 任务执行方法
     * @param taskName 任务名称
     * @param role 角色配置
     */
    @Role(roleDependencies = "[]")
    public void executeTask(String taskName, Role role) {
        List<String> dependencies = processor.processRoleDependencies(role);
        
        // 模拟任务处理逻辑
        if (dependencies.contains("critical_dependency")) {
            System.out.println("[任务系统] 依赖检查通过: " + taskName);
        } else {
            System.out.println("[任务系统] 依赖检查失败: " + taskName);
        }
    }
}