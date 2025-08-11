package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务管理控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    /**
     * 创建新任务
     * @param title 任务标题
     * @param model 视图模型
     * @return 重定向到任务列表
     */
    @PostMapping
    public String createTask(@RequestParam("title") String title, Model model) {
        if (title == null || title.trim().isEmpty()) {
            model.addAttribute("error", "标题不能为空");
            return "create-task";
        }

        // 验证标题格式
        if (!validateTaskTitle(title)) {
            model.addAttribute("error", "标题包含非法字符");
            return "create-task";
        }

        Task task = new Task();
        task.setTitle(title);
        taskService.save(task);
        
        return "redirect:/tasks";
    }

    /**
     * 获取所有任务
     * @param model 视图模型
     * @return 任务列表视图
     */
    @GetMapping
    public String getAllTasks(Model model) {
        List<Task> tasks = taskService.findAll();
        model.addAttribute("tasks", tasks);
        return "task-list";
    }

    /**
     * 显示任务详情
     * @param id 任务ID
     * @param model 视图模型
     * @return 任务详情视图
     */
    @GetMapping("/{id}")
    public String getTaskDetails(@PathVariable("id") Long id, Model model) {
        Task task = taskService.findById(id);
        if (task == null) {
            model.addAttribute("error", "任务不存在");
            return "error";
        }
        
        model.addAttribute("task", task);
        return "task-detail";
    }

    /**
     * 验证任务标题格式
     * @param title 待验证标题
     * @return 是否通过验证
     */
    private boolean validateTaskTitle(String title) {
        // 仅允许字母数字和空格
        return title.matches("[A-Za-z0-9 ]+");
    }
}