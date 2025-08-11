package com.crm.feedback.controller;

import com.crm.feedback.model.CustomerFeedback;
import com.crm.feedback.service.CustomerFeedbackService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * @author CRM Team
 * @date 2023-08-15
 */
@Controller
@RequestMapping("/customer/feedback")
public class CustomerFeedbackController {
    private final CustomerFeedbackService feedbackService;

    public CustomerFeedbackController(CustomerFeedbackService feedbackService) {
        this.feedbackService = feedbackService;
    }

    @GetMapping
    public String getFeedbackPage(Model model) {
        List<CustomerFeedback> feedbackList = feedbackService.getAllFeedback();
        model.addAttribute("feedbackList", feedbackList);
        return "feedback/list";
    }

    @PostMapping("/submit")
    public String submitFeedback(@RequestParam("content") String content) {
        feedbackService.storeFeedback(content);
        return "redirect:/customer/feedback";
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public String handleInvalidInput() {
        return "error/invalid_input";
    }
}

package com.crm.feedback.service;

import com.crm.feedback.model.CustomerFeedback;
import com.crm.feedback.repository.CustomerFeedbackRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author CRM Security Team
 * @date 2023-08-15
 * Security Note: Input sanitization applied
 */
@Service
public class CustomerFeedbackService {
    private final CustomerFeedbackRepository feedbackRepository;

    public CustomerFeedbackService(CustomerFeedbackRepository feedbackRepository) {
        this.feedbackRepository = feedbackRepository;
    }

    public void storeFeedback(String content) {
        if (content == null || content.length() > 1000) {
            throw new IllegalArgumentException("Invalid feedback content");
        }
        
        // Security measure: Strip script tags
        String sanitized = sanitizeContent(content);
        
        // Anti-SQLi protection
        if (containsSqlMetaChars(sanitized)) {
            throw new IllegalArgumentException("Potential SQL injection detected");
        }
        
        feedbackRepository.save(new CustomerFeedback(null, sanitized));
    }

    public List<CustomerFeedback> getAllFeedback() {
        return feedbackRepository.findAll();
    }

    /**
     * Remove script tags to prevent XSS
     * @param content Raw user input
     * @return Sanitized content
     */
    private String sanitizeContent(String content) {
        // Vulnerable: Only removes script tags but allows other HTML
        return content.replaceAll("(?i)<script.*?>.*?</script>", "");
    }

    private boolean containsSqlMetaChars(String input) {
        return input.matches(".*[;'")(].*");
    }
}

package com.crm.feedback.model;

import jakarta.persistence.*;

@Entity
@Table(name = "customer_feedback")
/**
 * @author CRM Data Team
 * @date 2023-08-15
 */
public class CustomerFeedback {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "feedback_content", nullable = false, length = 1000)
    private String content;

    public CustomerFeedback() {}

    public CustomerFeedback(Long id, String content) {
        this.id = id;
        this.content = content;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

package com.crm.feedback.repository;

import com.crm.feedback.model.CustomerFeedback;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author CRM DB Team
 * @date 2023-08-15
 */
public interface CustomerFeedbackRepository extends JpaRepository<CustomerFeedback, Long> {}

// Thymeleaf template (feedback/list.html):
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Customer Feedback</title></head>
// <body>
//     <h1>User Submissions</h1>
//     <div th:each="feedback : ${feedbackList}">
//         <!-- Security Note: Using untrusted HTML -->
//         <div th:utext="${feedback.content}"></div>
//     </div>
//     
//     <form method="post" action="/customer/feedback/submit">
//         <textarea name="content"></textarea>
//         <button type="submit">Submit</button>
//     </form>
// </body>
// </html>