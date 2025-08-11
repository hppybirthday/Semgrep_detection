package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @PostMapping("/batch")
    public String batchInsertTasks(@RequestBody List<Task> tasks,
                                   @RequestParam(name = "sort", required = false) String sortField) {
        if (taskService.validateTasks(tasks)) {
            taskService.processAndInsert(tasks, sortField);
            return "Tasks processed and inserted";
        }
        return "Invalid tasks";
    }
}

// -----------------------------

package com.example.taskmanager.service;

import com.example.taskmanager.dao.TaskMapper;
import com.example.taskmanager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public boolean validateTasks(List<Task> tasks) {
        return tasks != null && !tasks.isEmpty();
    }

    public void processAndInsert(List<Task> tasks, String sortField) {
        // 构建查询条件
        String finalSort = normalizeSortField(sortField);
        taskMapper.insertBatch(tasks, finalSort);
    }

    private String normalizeSortField(String sortField) {
        // 简单的字段格式校验
        if (sortField == null || sortField.isEmpty()) {
            return "created_at";
        }
        return sortField;
    }
}

// -----------------------------

package com.example.taskmanager.dao;

import com.example.taskmanager.model.Task;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TaskMapper {
    void insertBatch(@Param("tasks") List<Task> tasks, @Param("sortField") String sortField);
}

// -----------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.taskmanager.dao.TaskMapper">
    <insert id="insertBatch">
        INSERT INTO tasks (title, description, status)
        VALUES
        <foreach collection="tasks" item="task" separator=",">
            (#{task.title}, #{task.description}, #{task.status})
        </foreach>
        ORDER BY ${sortField}
    </insert>
</mapper>