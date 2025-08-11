// SimulationTask.java
package com.mathsim.model.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "simulation_tasks")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SimulationTask {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String modelName;

    @Column(columnDefinition = "TEXT")
    private String parameters; // Vulnerable field

    @Column(nullable = false)
    private String createdBy;
}

// SimulationService.java
package com.mathsim.model.service;

import com.mathsim.model.entity.SimulationTask;
import com.mathsim.model.repository.SimulationTaskRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SimulationService {
    private final SimulationTaskRepository taskRepository;

    public List<SimulationTask> getAllTasks() {
        return taskRepository.findAll();
    }

    public SimulationTask createTask(SimulationTask task) {
        // Vulnerable: Directly save user input without sanitization
        return taskRepository.save(task);
    }

    // Misleading safe method that's not actually used
    private String sanitizeInput(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>]", ""); // Incomplete sanitization
    }
}

// SimulationController.java
package com.mathsim.model.controller;

import com.mathsim.model.entity.SimulationTask;
import com.mathsim.model.service.SimulationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/simulations")
@RequiredArgsConstructor
public class SimulationController {
    private final SimulationService simulationService;

    @GetMapping
    public String listSimulations(Model model) {
        model.addAttribute("tasks", simulationService.getAllTasks());
        return "simulations/list";
    }

    @PostMapping
    public String createSimulation(@ModelAttribute SimulationTask task) {
        simulationService.createTask(task);
        return "redirect:/simulations";
    }
}

// list.html (Thymeleaf template)
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Simulations</title>
</head>
<body>
    <h1>Simulation Tasks</h1>
    <form th:action="@{/simulations}" th:object="${task}" method="post">
        <input type="text" th:field="*{modelName}" />
        <!-- Vulnerable context: User input directly in HTML attribute -->
        <input type="text" th:field="*{parameters}" value="${task.parameters}" />
        <button type="submit">Create</button>
    </form>

    <ul>
        <li th:each="task : ${tasks}">
            <strong th:text="${task.modelName}"></strong>
            <!-- Vulnerable output in attribute value context -->
            <input type="text" th:value="${task.parameters}" readonly />
            <small>Created by: <span th:text="${task.createdBy}"></span></small>
        </li>
    </ul>
</body>
</html>