package com.example.taskmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// 实体类
class Task {
    private int id;
    private String name;
    private String description;
    // 省略getter/setter
}

// Mapper接口
interface TaskMapper {
    List<Task> findTasksByName(String name);
}

// Service层
@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> searchTasks(String taskName) {
        // 存在漏洞的拼接方式
        String safeName = "'" + taskName.replace("'", "''") + "'";
        return taskMapper.findTasksByName(safeName);
    }
}

// Controller层
@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping("/search")
    public List<Task> searchTasks(@RequestParam String name) {
        return taskService.searchTasks(name);
    }
}

// Mapper XML配置
/*
<mapper namespace="com.example.taskmanager.TaskMapper">
    <select id="findTasksByName" resultType="Task">
        SELECT * FROM tasks WHERE name = ${name}
    </select>
</mapper>
*/

// 数据库表结构
/*
CREATE TABLE tasks (
    id INT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT
);
*/