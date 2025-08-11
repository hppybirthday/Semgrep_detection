package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteTasks(@RequestParam String ids) {
        // 模拟爬虫任务删除接口，直接将逗号分隔的字符串传递给服务层
        taskService.deleteTasksByIds(ids);
        return ResponseEntity.ok("Tasks deleted");
    }
}

@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public void deleteTasksByIds(String ids) {
        // 未校验输入格式，直接传递原始字符串到Mapper
        taskMapper.deleteTasksByIds(ids);
    }
}

@Mapper
interface TaskMapper {
    // 错误地使用${}进行SQL拼接，而非#{}参数化查询
    @Select("DELETE FROM tasks WHERE id IN (${ids})")
    void deleteTasksByIds(String ids);
    
    // MyBatis-Plus自带的removeByIds方法本应安全，但被错误覆盖
    // 假设开发者错误地认为字符串拼接是安全的
}

// 模拟实体类
class Task {
    private Long id;
    private String url;
    // 省略getter/setter
}

// 数据库表结构
/*
CREATE TABLE tasks (
    id BIGINT PRIMARY KEY,
    url VARCHAR(255),
    crawled BOOLEAN
);
*/