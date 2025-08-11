package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.util.SqlUtil;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping("/list")
    public List<Task> listTasks(@RequestParam(required = false) String sortField,
                                @RequestParam List<Long> taskIds) {
        // 处理排序字段安全转义
        String safeSortField = SqlUtil.escapeOrderBySql(sortField);
        // 应用排序策略
        PageHelper.orderBy(safeSortField);
        // 查询任务列表
        return taskService.getTasksByIds(taskIds);
    }
}

// --- Service Layer ---
package com.example.taskmanager.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.taskmanager.mapper.TaskMapper;
import com.example.taskmanager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> getTasksByIds(List<Long> taskIds) {
        QueryWrapper<Task> queryWrapper = new QueryWrapper<>();
        // 构造IN查询条件
        if (taskIds != null && !taskIds.isEmpty()) {
            queryWrapper.in("id", taskIds);
        }
        return taskMapper.selectList(queryWrapper);
    }
}

// --- Mapper XML ---
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.taskmanager.mapper.TaskMapper">
    <select id="selectList" resultType="com.example.taskmanager.model.Task">
        SELECT * FROM tasks
        <where>
            <if test="ew != null">
                ${ew.sqlSegment}
            </if>
        </where>
        <if test="ew.orderBySqlSegment != null">
            ${ew.orderBySqlSegment}
        </if>
    </select>
</mapper>