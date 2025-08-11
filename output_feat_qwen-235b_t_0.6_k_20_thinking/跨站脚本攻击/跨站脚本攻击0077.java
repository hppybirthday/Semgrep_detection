package com.example.mathmodeller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class MathModellerApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathModellerApplication.class, args);
    }
}

@Controller
class ModelController {
    private final ModelRepository modelRepository = new InMemoryModelRepository();

    @GetMapping("/models")
    public String listModels(Model model) {
        model.addAttribute("models", modelRepository.findAll());
        return "models/list";
    }

    @PostMapping("/models")
    public String createModel(@RequestParam String name, @RequestParam String formula) {
        MathModel mathModel = new MathModel(name, formula);
        modelRepository.save(mathModel);
        return "redirect:/models";
    }
}

interface ModelRepository {
    List<MathModel> findAll();
    void save(MathModel model);
}

class InMemoryModelRepository implements ModelRepository {
    private final List<MathModel> models = new ArrayList<>();

    @Override
    public List<MathModel> findAll() {
        return new ArrayList<>(models);
    }

    @Override
    public void save(MathModel model) {
        models.add(model);
    }
}

class MathModel {
    private final String name;
    private final String formula;

    public MathModel(String name, String formula) {
        this.name = name;
        this.formula = formula;
    }

    public String getName() { return name; }
    public String getFormula() { return formula; }
}

// Thymeleaf template (resources/templates/models/list.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1>Math Models</h1>
//     <div th:each="model : ${models}">
//         <div>
//             <strong>Name:</strong> [[${model.name}]]<br/>
//             <strong>Formula:</strong> [[${model.formula}]]
//         </div>
//     </div>
// </body>
// </html>