package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.ibatis.annotations.*;
import java.util.*;

@SpringBootApplication
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

// Entity
class Task {
    private Long id;
    private String title;
    private String description;
    private boolean completed;
    
    // Getters/Setters omitted for brevity
}

// Mapper
@Mapper
interface TaskMapper extends BaseMapper<Task> {
    @Select("SELECT * FROM tasks ORDER BY ${sortBy}")
    List<Task> selectTasksSortedBy(@Param("sortBy") String sortBy);
}

// Service
@Service
class TaskService extends ServiceImpl<TaskMapper, Task> {
    public List<Task> getTasksSortedBy(String sortBy) {
        return baseMapper.selectTasksSortedBy(sortBy);
    }

    public void batchDelete(String clients) {
        baseMapper.deleteClients(clients);
    }
}

// Mapper Additional Method
interface TaskMapper extends BaseMapper<Task> {
    @Select("SELECT * FROM tasks ORDER BY ${sortBy}")
    List<Task> selectTasksSortedBy(@Param("sortBy") String sortBy);
    
    @Delete("DELETE FROM tasks WHERE client_id IN (${clients})")
    void deleteClients(@Param("clients") String clients);
}

// Controller
@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    @GetMapping
    public List<Task> getAllTasks(@RequestParam String sortBy) {
        return taskService.getTasksSortedBy(sortBy);
    }

    @DeleteMapping
    public void deleteTasks(@RequestParam String clients) {
        taskService.batchDelete(clients);
    }
}