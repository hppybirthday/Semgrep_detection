package com.task.manager.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.task.manager.model.Task;
import com.task.manager.service.TaskService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务管理控制器
 * 提供任务删除接口
 */
@RestController
@Tag(name = "TaskController", description = "任务管理接口")
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @DeleteMapping("/delete")
    @Operation(summary = "批量删除任务", parameters = {
        @Parameter(name = "ids", description = "逗号分隔的任务ID列表", in = ParameterIn.QUERY)
    })
    public Result deleteTasks(@RequestParam String ids) {
        try {
            taskService.deleteTasks(ids);
            return Result.success("删除成功");
        } catch (Exception e) {
            return Result.error("删除失败: " + e.getMessage());
        }
    }
}

class Result {
    private boolean success;
    private String message;
    private Object data;

    public static Result success() {
        return new Result(true, null, null);
    }

    public static Result success(String message) {
        return new Result(true, message, null);
    }

    public static Result success(Object data) {
        return new Result(true, null, data);
    }

    public static Result error(String message) {
        return new Result(false, message, null);
    }

    private Result(boolean success, String message, Object data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }
}