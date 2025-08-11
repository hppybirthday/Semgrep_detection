package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.mapper.BaseMapper;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api/tasks")
public class VulnerableCrawlerApp {
    @Autowired
    private TaskService taskService;

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApp.class, args);
    }

    @GetMapping("/delete")
    public String deleteTasks(@RequestParam String ids) {
        // 漏洞触发点：直接将用户输入拼接到SQL语句中
        taskService.deleteTasks(ids);
        return "Tasks deleted";
    }

    static class Task {
        private Integer id;
        private String url;
        // getters and setters
    }
}

interface TaskMapper extends BaseMapper<VulnerableCrawlerApp.Task> {
    // 漏洞点：使用字符串拼接方式构造SQL
    @SQL("DELETE FROM tasks WHERE id IN (${ids})")
    void deleteTasks(String ids);
}

@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    void deleteTasks(String ids) {
        // 漏洞成因：未对输入参数做任何校验直接传递给SQL层
        taskMapper.deleteTasks(ids);
    }
}
// 数据库表结构：
// CREATE TABLE tasks (
//     id INT PRIMARY KEY,
//     url VARCHAR(255)
// );