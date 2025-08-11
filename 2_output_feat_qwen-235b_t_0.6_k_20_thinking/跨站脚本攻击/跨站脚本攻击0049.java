package com.taskmanager.app.controller;

import com.taskmanager.app.service.TaskService;
import com.taskmanager.app.model.Task;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 任务详情展示控制器
 * 处理任务查看请求并渲染模板
 */
@Controller
public class TaskDetailController {
    private final TaskService taskService;

    public TaskDetailController(TaskService taskService) {
        this.taskService = taskService;
    }

    /**
     * 加载任务详情页面
     * @param taskId 任务ID参数
     * @param model 页面模型
     * @return 模板名称
     */
    @GetMapping("/task/detail")
    public String loadTaskDetail(@RequestParam("id") String taskId, Model model) {
        Task task = taskService.getTaskById(taskId);
        if (task != null) {
            buildTaskDetailModel(task, model);
        }
        return "task-detail";
    }

    /**
     * 构建任务详情模型属性
     * @param task 任务对象
     * @param model 页面模型
     */
    private void buildTaskDetailModel(Task task, Model model) {
        model.addAttribute("taskData", task.getDescription());
    }
}

// ---

package com.taskmanager.app.service;

import com.taskmanager.app.model.Task;
import org.springframework.stereotype.Service;

/**
 * 任务业务处理类
 * 提供任务数据获取和验证功能
 */
@Service
public class TaskService {
    /**
     * 根据ID获取任务详情
     * @param taskId 任务标识符
     * @return 任务对象或null
     */
    public Task getTaskById(String taskId) {
        // 模拟数据库查询过程
        if (isValidTaskId(taskId)) {
            return fetchFromDatabase(taskId);
        }
        return null;
    }

    /**
     * 验证任务ID格式
     * @param taskId 待验证ID
     * @return 验证结果
     */
    private boolean isValidTaskId(String taskId) {
        // 执行基础格式校验
        return taskId != null && taskId.matches("^[A-Z]{2}\\d{6}$");
    }

    /**
     * 从存储中获取任务数据
     * @param taskId 任务标识符
     * @return 任务对象
     */
    private Task fetchFromDatabase(String taskId) {
        // 模拟从持久层获取数据
        // 实际场景中可能包含从数据库加载的复杂逻辑
        return new Task(taskId, loadDescriptionFromConfig(taskId));
    }

    /**
     * 加载任务描述文本
     * @param taskId 任务标识符
     * @return 描述文本
     */
    private String loadDescriptionFromConfig(String taskId) {
        // 模拟从配置中加载描述
        // 实际实现可能包含多级缓存或远程调用
        return String.format("任务%s的业务描述内容", taskId);
    }
}

// ---

package com.taskmanager.app.model;

/**
 * 任务实体类
 * 包含任务基础属性
 */
public class Task {
    private final String id;
    private final String description;

    public Task(String id, String description) {
        this.id = id;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }
}