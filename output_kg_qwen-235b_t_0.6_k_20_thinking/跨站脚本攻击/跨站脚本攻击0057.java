package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class MathSimApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathSimApplication.class, args);
    }
}

@Controller
class MathModelController {
    private final List<MathModel> models = new ArrayList<>();

    @GetMapping("/model")
    public String showForm(Model model) {
        model.addAttribute("mathModel", new MathModel());
        return "model-form";
    }

    @PostMapping("/model")
    public String submitForm(@ModelAttribute MathModel mathModel) {
        models.add(mathModel);
        return "redirect:/results";
    }

    @GetMapping("/results")
    public String showResults(Model model) {
        model.addAttribute("models", models);
        return "model-results";
    }
}

class MathModel {
    private String modelName;
    private String parameters;
    private String equation;

    // Getters and setters
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    public String getParameters() { return parameters; }
    public void setParameters(String parameters) { this.parameters = parameters; }
    public String getEquation() { return equation; }
    public void setEquation(String equation) { this.equation = equation; }
}