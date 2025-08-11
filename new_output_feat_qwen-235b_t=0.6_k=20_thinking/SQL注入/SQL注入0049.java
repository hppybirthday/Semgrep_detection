package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.dto.TaskDTO;
import com.example.taskmanager.common.ApiResponse;
import com.example.taskmanager.common.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping
    public ApiResponse<PageResult<TaskDTO>> listTasks(
            @RequestParam(required = false) String taskName,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortField,
            @RequestParam(required = false) String sortOrder) {
        
        List<TaskDTO> tasks = taskService.getTasks(taskName, status, pageNum, pageSize, sortField, sortOrder);
        int total = taskService.countTasks(taskName, status);
        
        return ApiResponse.success(new PageResult<>(tasks, total, pageNum, pageSize));
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.mapper.TaskMapper;
import com.example.taskmanager.dto.TaskDTO;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<TaskDTO> getTasks(String taskName, String status, int pageNum, int pageSize, String sortField, String sortOrder) {
        Page<TaskDTO> page = new Page<>(pageNum, pageSize);
        
        String orderByClause = "create_time DESC";
        if (sortField != null && sortOrder != null) {
            orderByClause = buildOrderByClause(sortField, sortOrder);
        }
        
        return taskMapper.selectPage(page, buildQueryWrapper(taskName, status), orderByClause).getRecords();
    }

    private QueryWrapper<TaskDTO> buildQueryWrapper(String taskName, String status) {
        QueryWrapper<TaskDTO> wrapper = new QueryWrapper<>();
        if (taskName != null && !taskName.isEmpty()) {
            wrapper.like("task_name", taskName);
        }
        if (status != null && !status.isEmpty()) {
            wrapper.eq("status", status);
        }
        return wrapper;
    }

    private int countTasks(String taskName, String status) {
        return taskMapper.selectCount(buildQueryWrapper(taskName, status));
    }

    private String buildOrderByClause(String sortField, String sortOrder) {
        // 模拟安全检查的误导性代码
        if (sortOrder.equalsIgnoreCase("ASC") || sortOrder.equalsIgnoreCase("DESC")) {
            return sortField + " " + sortOrder;
        }
        return "create_time DESC";
    }
}

package com.example.taskmanager.mapper;

import com.example.taskmanager.dto.TaskDTO;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface TaskMapper extends BaseMapper<TaskDTO> {
    @org.apache.ibatis.annotations.Select({"<script>",
      "SELECT * FROM tasks WHERE 1=1",
      "<if test='taskName != null'> AND task_name LIKE CONCAT('%', #{taskName}, '%') </if>",
      "<if test='status != null'> AND status = #{status} </if>",
      "ORDER BY ${orderByClause}",
      "</script>"})
    List<TaskDTO> selectPage(@Param("taskName") String taskName, 
                            @Param("status") String status, 
                            @Param("orderByClause") String orderByClause);
}

package com.example.taskmanager.dto;

import lombok.Data;

@Data
public class TaskDTO {
    private Long id;
    private String taskName;
    private String status;
    private String description;
    private Long createTime;
}

package com.example.taskmanager.common;

import lombok.Data;

@Data
public class PageResult<T> {
    private List<T> data;
    private int pageNum;
    private int pageSize;
    private long total;

    public PageResult(List<T> data, long total, int pageNum, int pageSize) {
        this.data = data;
        this.total = total;
        this.pageNum = pageNum;
        this.pageSize = pageSize;
    }
}

package com.example.taskmanager.common;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(200);
        response.setMessage("Success");
        response.setData(data);
        return response;
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(code);
        response.setMessage(message);
        return response;
    }
}