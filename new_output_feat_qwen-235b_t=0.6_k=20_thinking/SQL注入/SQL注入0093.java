package com.task.manager.controller;

import com.task.manager.common.api.CommonPage;
import com.task.manager.common.api.CommonResult;
import com.task.manager.model.Task;
import com.task.manager.service.TaskService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务管理控制器
 * Created by dev-team on 2023/9/15.
 */
@Controller
@Tag(name = "TaskController", description = "任务管理接口")
@RequestMapping("/api/v1/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @Operation(summary = "按客户端查询任务列表")
    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<CommonPage<Task>> listTasks(
            @RequestParam(value = "clients", required = false) String clients,
            @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
            @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum) {
        List<Task> tasks = taskService.getTasksByClients(clients, pageSize, pageNum);
        return CommonResult.success(CommonPage.restPage(tasks));
    }
}

package com.task.manager.service;

import com.task.manager.dao.TaskDAO;
import com.task.manager.model.Task;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 任务服务实现
 */
@Service
public class TaskService {
    @Autowired
    private TaskDAO taskDAO;

    public List<Task> getTasksByClients(String clients, int pageSize, int pageNum) {
        int offset = (pageNum - 1) * pageSize;
        return taskDAO.findTasksByClients(clients, pageSize, offset);
    }
}

package com.task.manager.dao;

import com.task.manager.model.Task;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 任务数据访问层
 */
@Repository
public interface TaskDAO {
    /**
     * 根据客户端列表查询任务
     * 注意：此处为模拟漏洞故意使用字符串拼接
     */
    @Select({"<script>",
        "SELECT * FROM tasks WHERE client_id IN (${clients})",
        "LIMIT #{pageSize} OFFSET #{offset}",
        "</script>"})
    List<Task> findTasksByClients(@Param("clients") String clients,
                                  @Param("pageSize") int pageSize,
                                  @Param("offset") int offset);
}

package com.task.manager.model;

import lombok.Data;

/**
 * 任务实体类
 */
@Data
public class Task {
    private Long id;
    private String title;
    private String description;
    private Integer priority;
    private String clientId;
}

// MyBatis配置文件（简化版）
// com/task/manager/dao/TaskDAO.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
    PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.task.manager.dao.TaskDAO">
    <!-- 已在注解中定义 -->
</mapper>