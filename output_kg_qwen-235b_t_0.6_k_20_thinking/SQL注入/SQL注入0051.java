package com.example.taskmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping("/search")
    public List<Task> searchTasks(@RequestParam String keyword) {
        return taskService.searchTasks(keyword);
    }
}

@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> searchTasks(String keyword) {
        return taskMapper.searchTasks(keyword);
    }
}

interface TaskMapper {
    @Select("SELECT * FROM tasks WHERE name LIKE '%${keyword}%'")
    List<Task> searchTasks(String keyword);
}

class Task {
    private int id;
    private String name;
    private String description;
    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// MyBatis configuration and other necessary components are assumed to exist