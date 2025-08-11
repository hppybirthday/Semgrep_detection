package com.crm.xss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

@Controller
class FeedbackController {
    static List<String> feedbacks = new ArrayList<>();

    @GetMapping("/feedback")
    public String showFeedbackForm() {
        return "feedback";
    }

    @PostMapping("/feedback")
    public String submitFeedback(@RequestParam String content) {
        feedbacks.add(content);
        return "redirect:/feedbacks";
    }

    @GetMapping("/feedbacks")
    public String showAllFeedbacks(Model model) {
        model.addAttribute("feedbacks", feedbacks);
        return "feedbacks";
    }
}

// templates/feedback.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
// <h1>Submit Feedback</h1>
// <form action="/feedback" method="post">
//   <textarea name="content"></textarea>
//   <button type="submit">Send</button>
// </form>
// </body>
// </html>

// templates/feedbacks.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
// <h1>All Feedbacks</h1>
// <div th:each="feedback : ${feedbacks}">
//   <p th:text="${feedback}"></p>  // Vulnerable line: No HTML escaping
// </div>
// </body>
// </html>