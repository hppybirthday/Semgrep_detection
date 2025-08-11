package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@SpringBootApplication
public class MathSimApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathSimApplication.class, args);
    }
}

@Controller
class ODEController {
    @GetMapping("/solve")
    public String solveEquation(@RequestParam("equation") String equation, Model model) {
        try {
            ODESolver solver = new ODESolver(equation);
            model.addAttribute("result", solver.solve());
        } catch (MathModelException e) {
            model.addAttribute("errorMessage", e.getMessage());
        }
        return "result";
    }
}

class MathModelException extends Exception {
    public MathModelException(String message) {
        super(message);
    }
}

class ODESolver {
    private String equation;

    public ODESolver(String equation) throws MathModelException {
        if (equation == null || equation.trim().isEmpty()) {
            throw new MathModelException("Equation cannot be empty");
        }
        this.equation = equation;
    }

    public String solve() throws MathModelException {
        // 模拟数学建模过程中的校验
        if (equation.contains("<script>") || equation.contains("</script>")) {
            throw new MathModelException("Invalid equation format: " + equation);
        }
        // 实际数学求解逻辑（简化）
        return "Solution for " + equation;
    }
}