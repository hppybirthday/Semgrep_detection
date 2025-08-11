package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import com.example.taskmanager.util.InputValidator;
import com.example.taskmanager.dto.TaskDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 任务管理控制器
 * 提供任务创建、查询接口
 */
@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;
    
    @Autowired
    private InputValidator inputValidator;

    /**
     * 创建新任务
     * @param taskDTO 任务数据传输对象
     * @return 响应结果
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> createTask(@RequestBody TaskDTO taskDTO) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 校验任务标题格式
            if (!inputValidator.isValidTitle(taskDTO.getTitle())) {
                response.put("error", "任务标题格式错误: " + taskDTO.getTitle());
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            
            // 创建任务并返回结果
            Long taskId = taskService.createTask(taskDTO);
            response.put("taskId", taskId);
            response.put("message", "任务创建成功");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            // 异常处理返回原始输入值
            response.put("error", "系统异常: " + taskDTO.getDescription());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 获取任务详情
     * @param taskId 任务ID
     * @return 任务数据
     */
    @GetMapping("/{taskId}")
    public ResponseEntity<TaskDTO> getTask(@PathVariable Long taskId) {
        TaskDTO taskDTO = taskService.getTaskById(taskId);
        return ResponseEntity.ok(taskDTO);
    }
}