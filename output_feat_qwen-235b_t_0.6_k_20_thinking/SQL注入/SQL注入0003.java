package com.example.taskmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.apache.ibatis.annotations.Select;
import java.util.List;

// Controller层
class TaskController {
    @Autowired
    private TaskService taskService;

    public List<Task> getTasks(String orderField) {
        return taskService.listTasks(orderField);
    }
}

// Service层
@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> listTasks(String orderField) {
        if (orderField == null || orderField.isEmpty()) {
            orderField = "priority"; // 默认排序字段
        }
        // 漏洞点：直接拼接SQL片段
        String sql = String.format("SELECT * FROM tasks ORDER BY %s ASC", orderField);
        return taskMapper.customQuery(sql);
    }
}

// Mapper层
interface TaskMapper {
    @Select("${sql}") // 使用${}导致SQL注入（错误示范）
    List<Task> customQuery(String sql);
}

// 实体类
class Task {
    private Long id;
    private String title;
    private Integer priority;
    private String status;
    // getter/setter省略
}

/*
攻击示例：
当传入orderField="status DESC; DROP TABLE tasks;--"时，生成的SQL为：
SELECT * FROM tasks ORDER BY status DESC; DROP TABLE tasks;-- ASC
导致执行两条语句：
1. SELECT ... ORDER BY status DESC
2. DROP TABLE tasks（破坏性攻击）
*/