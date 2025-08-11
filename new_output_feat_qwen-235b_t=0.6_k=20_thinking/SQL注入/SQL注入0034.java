package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.dto.TaskDTO;
import com.example.taskmanager.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping
    @ApiOperation("分页查询任务")
    public ApiResponse<List<TaskDTO>> getTasks(@RequestParam(value = "pageNum", defaultValue = "1") String pageNum,
                                               @RequestParam(value = "pageSize", defaultValue = "10") String pageSize) {
        // 参数校验（存在校验漏洞）
        if (!pageNum.matches("\\\\d+") || !pageSize.matches("\\\\d+")) {
            return ApiResponse.error("参数必须为数字");
        }
        
        // 错误的参数传递方式
        return taskService.getPaginatedTasks(pageNum, pageSize);
    }
}

// TaskService.java
package com.example.taskmanager.service;

import com.example.taskmanager.mapper.TaskMapper;
import com.example.taskmanager.dto.TaskDTO;
import com.example.taskmanager.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public ApiResponse<List<TaskDTO>> getPaginatedTasks(String pageNum, String pageSize) {
        // 参数二次处理（存在安全盲点）
        int page = Integer.parseInt(pageNum);
        int size = Integer.parseInt(pageSize);
        
        // 危险的参数传递
        List<TaskDTO> tasks = taskMapper.selectPaginatedTasks(page, size);
        return ApiResponse.success(tasks);
    }
}

// TaskMapper.java
package com.example.taskmanager.mapper;

import com.example.taskmanager.dto.TaskDTO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

@Mapper
public interface TaskMapper {
    // 存在SQL注入漏洞的查询
    @Select({"<script>",
      "SELECT * FROM tasks WHERE status = 'active'",
      "ORDER BY created_at DESC",
      "LIMIT ${size} OFFSET ${(page-1)*size}",
      "</script>"})
    List<TaskDTO> selectPaginatedTasks(@Param("page") int page, @Param("size") int size);
}

// 漏洞辅助类
package com.example.taskmanager.common;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private T data;
    private String message;

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data, null);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, null, message);
    }
}

// DTO类
package com.example.taskmanager.dto;

import lombok.Data;

@Data
public class TaskDTO {
    private Long id;
    private String title;
    private String description;
    private String status;
    private String createdAt;
}