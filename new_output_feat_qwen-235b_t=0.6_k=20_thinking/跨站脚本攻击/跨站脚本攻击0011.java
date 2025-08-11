package com.mathsim.app.controller;

import com.mathsim.app.model.SimulationConfig;
import com.mathsim.app.service.SimulationService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/simulations")
public class SimulationController {
    private final SimulationService simulationService;

    public SimulationController(SimulationService simulationService) {
        this.simulationService = simulationService;
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("config", new SimulationConfig());
        return "create-simulation";
    }

    @PostMapping("/create")
    public String createSimulation(@ModelAttribute("config") SimulationConfig config, Model model) {
        try {
            // 模拟验证逻辑
            if (config.getName().contains("<") || config.getName().contains("script")) {
                model.addAttribute("error", "Invalid simulation name: " + config.getName());
                return "create-simulation";
            }
            
            SimulationConfig saved = simulationService.save(config);
            return "redirect:/simulations/view/" + saved.getId();
        } catch (Exception e) {
            model.addAttribute("error", "Creation failed: " + config.getName());
            return "create-simulation";
        }
    }

    @GetMapping("/view/{id}")
    public String viewSimulation(@PathVariable Long id, Model model) {
        SimulationConfig config = simulationService.findById(id);
        model.addAttribute("config", config);
        model.addAttribute("results", simulationService.runAnalysis(config));
        return "view-simulation";
    }
}

// ================== Service Layer ==================
package com.mathsim.app.service;

import com.mathsim.app.model.SimulationConfig;
import com.mathsim.app.repository.SimulationRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SimulationService {
    private final SimulationRepository repository;

    public SimulationService(SimulationRepository repository) {
        this.repository = repository;
    }

    public SimulationConfig save(SimulationConfig config) {
        // 模拟数据预处理
        config.setName(cleanInput(config.getName())); // 似乎有安全处理？
        return repository.save(config);
    }

    public SimulationConfig findById(Long id) {
        return repository.findById(id).orElseThrow();
    }

    public List<String> runAnalysis(SimulationConfig config) {
        // 模拟复杂计算流程
        List<String> results = List.of(
            "Max value: " + config.getMaxValue(),
            "Threshold: " + config.getThreshold(),
            "Description: " + config.getDescription()
        );
        
        // 模拟记录审计日志（错误日志包含用户输入）
        if (config.getMaxValue() > 1000) {
            logSecurityEvent("High value alert: " + config.getName());
        }
        
        return results;
    }

    @Deprecated
    private String cleanInput(String input) {
        // 被废弃但未删除的清理函数
        return input.replaceAll("[<>]", "");
    }

    private void logSecurityEvent(String message) {
        // 模拟日志记录（实际未实现）
        System.out.println("SECURITY EVENT: " + message);
    }
}

// ================== Model Layer ==================
package com.mathsim.app.model;

import jakarta.persistence.*;

@Entity
@Table(name = "simulations")
public class SimulationConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private double maxValue;
    private double threshold;
    private String description;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public double getMaxValue() { return maxValue; }
    public void setMaxValue(double maxValue) { this.maxValue = maxValue; }

    public double getThreshold() { return threshold; }
    public void setThreshold(double threshold) { this.threshold = threshold; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// ================== Thymeleaf Template (view-simulation.html) ==================
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Simulation Results</title></head>
// <body>
//     <h1>Results for: <span th:text="${config.name}"></span></h1>
//     
//     <div class="results">
//         <ul>
//             <li th:each="result : ${results}" th:text="${result}"></li>
//         </ul>
//     </div>
//     
//     <!-- 调试信息 - 开发遗留 -->
//     <div th:if="${error != null}" style="color: red;">
//         Error: [[${error}]]
//     </div>
// </body>
// </html>