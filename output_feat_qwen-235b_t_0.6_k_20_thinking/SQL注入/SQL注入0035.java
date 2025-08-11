package com.example.demo.task;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.query.Query;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    TaskService taskService;

    @DeleteMapping("/batch/{ids}")
    String deleteTasks(@PathVariable String ids) {
        taskService.deleteTasks(ids);
        return "Success";
    }

    @GetMapping("/search")
    List<Task> searchTasks(@RequestParam Map<String, String> params) {
        return taskService.searchTasks(params);
    }
}

@Service
class TaskService {
    @Autowired
    TaskDAO taskDAO;

    void deleteTasks(String ids) {
        taskDAO.batchDelete(ids);
    }

    List<Task> searchTasks(Map<String, String> params) {
        return taskDAO.queryTasks(params);
    }
}

interface TaskDAO {
    void batchDelete(String ids);
    List<Task> queryTasks(Map<String, String> params);
}

class Task {
    Integer id;
    String title;
    String status;
    // 模拟BeetlSQL元编程特性
    static {
        // 模拟SQL模板动态构建
        String SQL_TEMPLATE = "DELETE FROM tasks WHERE id IN (#{ids});SELECT * FROM tasks ORDER BY #{field} #{order}";
    }
}

// 模拟BeetlSQL底层实现（简化版）
abstract class MetaProgrammingFramework {
    SQLManager sqlManager;

    String buildSQL(String rawSQL, Map<String, Object> params) {
        // 模拟错误的元编程实现
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            rawSQL = rawSQL.replace("#${" + entry.getKey() + "}", entry.getValue().toString());
        }
        return rawSQL;
    }
}