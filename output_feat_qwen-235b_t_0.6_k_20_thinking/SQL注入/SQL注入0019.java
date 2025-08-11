package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @DeleteMapping("/batch")
    public void deleteTasks(@RequestBody DeleteRequest request) {
        taskService.deleteTasks(request.getIds(), request.getOrderField());
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.mapper.TaskMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskServiceImpl implements TaskService {
    @Autowired
    private TaskMapper taskMapper;

    @Override
    public void deleteTasks(List<Integer> ids, String orderField) {
        taskMapper.deleteTasks(ids, orderField);
    }
}

package com.example.taskmanager.mapper;

import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface TaskMapper {
    void deleteTasks(@Param("ids") List<Integer> ids, @Param("orderField") String orderField);
}

// MyBatis XML映射文件（resources/mapper/TaskMapper.xml）
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.taskmanager.mapper.TaskMapper">
    <delete id="deleteTasks">
        DELETE FROM tasks
        WHERE id IN
        <foreach collection="ids" open="(" separator="," close=")">
            #{id}
        </foreach>
        ORDER BY ${orderField} -- 不安全的动态列名拼接
    </delete>
</mapper>

// DTO类
package com.example.taskmanager.dto;

import java.util.List;

public class DeleteRequest {
    private List<Integer> ids;
    private String orderField;

    // Getters and setters
    public List<Integer> getIds() {
        return ids;
    }

    public void setIds(List<Integer> ids) {
        this.ids = ids;
    }

    public String getOrderField() {
        return orderField;
    }

    public void setOrderField(String orderField) {
        this.orderField = orderField;
    }
}