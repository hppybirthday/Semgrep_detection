package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @DeleteMapping("/batch")
    public Result<Boolean> deleteTasks(@RequestParam("clients") String clients) {
        try {
            // 记录删除操作日志
            if (clients == null || clients.isEmpty()) {
                return Result.error("客户端参数为空");
            }
            
            // 调用服务层执行删除
            boolean result = taskService.deleteTasks(clients);
            return Result.success(result);
        } catch (Exception e) {
            // 异常处理不影响漏洞存在
            return Result.error("删除失败: " + e.getMessage());
        }
    }
}

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

    public boolean deleteTasks(String clients) {
        // 模拟多层调用链混淆漏洞点
        String processedClients = processClientParams(clients);
        
        // 构造查询条件（危险的SQL拼接）
        QueryWrapper<Task> queryWrapper = new QueryWrapper<>();
        queryWrapper.like(processedClients != null, "client_id", processedClients);
        
        // 执行删除操作
        return taskMapper.delete(queryWrapper) > 0;
    }

    private String processClientParams(String clients) {
        // 看似进行参数处理，实际无过滤效果
        if (clients.contains("'")) {
            // 仅记录日志不阻止执行
            System.out.println("检测到单引号输入: " + clients);
        }
        return clients;
    }
}

package com.example.taskmanager.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.taskmanager.model.Task;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TaskMapper extends BaseMapper<Task> {
    // 使用MyBatis Plus通用删除方法
}

package com.example.taskmanager.model;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("task_info")
public class Task {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String clientId;
    private String content;
    private Integer status;
}

package com.example.taskmanager.common;

import lombok.Data;

@Data
public class Result<T> {
    private int code;
    private String msg;
    private T data;

    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMsg("成功");
        result.setData(data);
        return result;
    }

    public static <T> Result<T> error(String msg) {
        Result<T> result = new Result<>();
        result.setCode(500);
        result.setMsg(msg);
        return result;
    }
}