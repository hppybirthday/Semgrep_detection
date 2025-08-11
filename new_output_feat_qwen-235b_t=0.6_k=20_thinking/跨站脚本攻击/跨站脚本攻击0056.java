package com.example.simulation.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "simulation_models")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SimulationModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String modelTitle;

    @Column(columnDefinition = "TEXT")
    private String modelDescription;

    @Column(nullable = false)
    private Integer maxIteration;
}

// ---

package com.example.simulation.repository;

import com.example.simulation.model.SimulationModel;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SimulationModelRepository extends JpaRepository<SimulationModel, Long> {
    List<SimulationModel> findByModelTitleContaining(String title);
}

// ---

package com.example.simulation.service;

import com.example.simulation.model.SimulationModel;
import com.example.simulation.repository.SimulationModelRepository;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SimulationModelService {
    private final SimulationModelRepository repository;

    public SimulationModelService(SimulationModelRepository repository) {
        this.repository = repository;
    }

    public List<SimulationModel> searchModels(String title) {
        return repository.findByModelTitleContaining(title);
    }

    public SimulationModel saveModel(SimulationModel model) {
        validateModel(model);
        return repository.save(model);
    }

    private void validateModel(SimulationModel model) {
        if (model.getMaxIteration() < 0 || model.getMaxIteration() > 10000) {
            throw new IllegalArgumentException("Invalid iteration count");
        }
        
        if (model.getModelTitle().length() > 50) {
            throw new IllegalArgumentException(
                "Model title too long: " + model.getModelTitle()
            );
        }
    }
}

// ---

package com.example.simulation.controller;

import com.example.simulation.model.SimulationModel;
import com.example.simulation.service.SimulationModelService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Controller
@RequestMapping("/models")
public class SimulationModelController {
    private final SimulationModelService service;

    public SimulationModelController(SimulationModelService service) {
        this.service = service;
    }

    @GetMapping
    public String listModels(@RequestParam(required = false) String title, Model model) {
        List<SimulationModel> models = (title == null) ? 
            service.searchModels("") : service.searchModels(title);
        model.addAttribute("models", models);
        return "model-list";
    }

    @PostMapping
    public String createModel(@ModelAttribute SimulationModel model) {
        service.saveModel(model);
        return "redirect:/models";
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleValidationError(IllegalArgumentException ex, Model model) {
        model.addAttribute("error", ex.getMessage());
        return "error-page";
    }
}

// ---

package com.example.simulation.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/error").setViewName("error-page");
    }
}

// ---

// templates/model-list.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Simulation Models</title></head>
// <body>
//     <h1>Model List</h1>
//     <div th:each="model : ${models}">
//         <h3 th:text="${model.modelTitle}"></h3>
//         <p th:utext="${model.modelDescription}"></p>
//     </div>
// </body>
// </html>

// templates/error-page.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Error</title></head>
// <body>
//     <div class="error" th:text="${error}"></div>
// </body>
// </html>