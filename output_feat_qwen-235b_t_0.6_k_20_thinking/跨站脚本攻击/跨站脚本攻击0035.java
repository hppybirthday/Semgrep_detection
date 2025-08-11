package com.example.taskmanager.controller;

import com.example.taskmanager.model.TaskCategory;
import com.example.taskmanager.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {
    @Autowired
    private TaskService taskService;

    @GetMapping("/categories")
    public String listCategories(Model model) {
        List<TaskCategory> categories = taskService.getAllCategories();
        model.addAttribute("categories", categories);
        return "admin/categories";
    }

    @PostMapping("/addCategory")
    public String addCategory(@RequestParam("name") String name) {
        TaskCategory category = new TaskCategory();
        category.setName(name);
        taskService.saveCategory(category);
        return "redirect:/admin/categories";
    }

    @GetMapping("/task/{id}")
    public String viewTask(@PathVariable("id") Long id, Model model) {
        TaskCategory category = taskService.getCategoryById(id);
        model.addAttribute("category", category);
        return "admin/task";
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.model.TaskCategory;
import com.example.taskmanager.repository.TaskCategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TaskService {
    @Autowired
    private TaskCategoryRepository categoryRepository;

    public List<TaskCategory> getAllCategories() {
        return categoryRepository.findAll();
    }

    public void saveCategory(TaskCategory category) {
        categoryRepository.save(category);
    }

    public TaskCategory getCategoryById(Long id) {
        return categoryRepository.findById(id).orElse(null);
    }
}

package com.example.taskmanager.model;

import javax.persistence.*;

@Entity
public class TaskCategory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;

    // Getters and setters
}

// Thymeleaf template: admin/categories.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Categories</title>
</head>
<body>
    <h1>Task Categories</h1>
    <form action="/admin/addCategory" method="post">
        <input type="text" name="name" />
        <button type="submit">Add</button>
    </form>
    <ul>
        <li th:each="category : ${categories}" th:text="${category.name}"></li>
    </ul>
</body>
</html>
*/