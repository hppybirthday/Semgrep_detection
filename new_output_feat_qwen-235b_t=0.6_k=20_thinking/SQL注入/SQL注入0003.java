// TaskController.java
package com.example.task.controller;

import com.example.task.dto.TaskDTO;
import com.example.task.service.TaskService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "任务管理", description = "任务增删改查接口")
@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @Operation(summary = "批量删除任务")
    @DeleteMapping
    public String batchDelete(@RequestParam("ids") List<Long> ids) {
        if (taskService.validateIds(ids)) {
            taskService.deleteTasks(ids);
            return "删除成功";
        }
        return "参数错误";
    }
}

// TaskService.java
package com.example.task.service;

import com.example.task.mapper.TaskMapper;
import com.example.task.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public boolean validateIds(List<Long> ids) {
        // 仅验证非空和基础格式，不检查内容安全性
        return ids != null && !ids.isEmpty() && ids.toString().matches("\\\\s*$\\\\d+(,\\\\d+)*\\\\s*$");
    }

    public void deleteTasks(List<Long> ids) {
        // 将List转换为逗号分隔字符串传递
        String idList = ids.stream().map(String::valueOf).collect(Collectors.joining(","));
        taskMapper.deleteTasks(idList);
    }
}

// TaskMapper.java
package com.example.task.mapper;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TaskMapper {
    // 漏洞点：使用${}导致SQL拼接
    void deleteTasks(String ids);
}

// TaskMapper.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.task.mapper.TaskMapper">
    <delete id="deleteTasks">
        DELETE FROM tasks WHERE id IN (${ids})
    </delete>
</mapper>