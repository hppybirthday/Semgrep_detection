package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }
}

@Controller
class ModelController {
    private final List<ModelInfo> models = new ArrayList<>();

    @GetMapping("/models")
    public String listModels(Model model) {
        model.addAttribute("models", models);
        return "models";
    }

    @PostMapping("/models")
    public String addModel(@RequestParam String description) {
        models.add(new ModelInfo(description));
        return "redirect:/models";
    }
}

class ModelInfo {
    String description;

    ModelInfo(String description) {
        this.description = description;
    }

    String getDescription() {
        return description;
    }
}