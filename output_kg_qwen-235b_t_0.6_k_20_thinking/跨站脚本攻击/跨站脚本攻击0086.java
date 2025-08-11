package com.crm.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;

@SpringBootApplication
@RestController
public class CrmXssDemoApplication {
    private static final ConcurrentHashMap<String, String> customerFeedback = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(CrmXssDemoApplication.class, args);
    }

    @GetMapping("/submit-feedback")
    public Function<HttpServletRequest, String> submitFeedback() {
        return req -> {
            String customer = req.getParameter("customer");
            String feedback = req.getParameter("feedback");
            
            // Vulnerable: Directly storing raw user input without sanitization
            if (customer != null && feedback != null) {
                customerFeedback.put(customer, feedback);
                return "<html><body>Feedback submitted for: " + customer + "</body></html>";
            }
            return "<html><body>Invalid input</body></html>";
        };
    }

    @GetMapping("/view-feedback")
    public Function<HttpServletRequest, String> viewFeedback() {
        return req -> {
            String customer = req.getParameter("customer");
            
            // Vulnerable: Directly injecting user-controlled data into HTML response
            if (customer != null && customerFeedback.containsKey(customer)) {
                String feedback = customerFeedback.get(customer);
                return "<html><body>"
                    + "<h3>Feedback for " + customer + ":</h3>"
                    + "<div style='border:1px solid'>" + feedback + "</div>"
                    + "</body></html>";
            }
            return "<html><body>No feedback found</body></html>";
        };
    }

    // Simulated CRM dashboard with vulnerable search feature
    @GetMapping("/dashboard")
    public String dashboard(@RequestParam(required = false) String search) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>")
            .append("<form method='get' action='/dashboard'>")
            .append("Search customers: <input type='text' name='search'>")
            .append("<input type='submit' value='Search'>")
            .append("</form>");

        if (search != null) {
            // Vulnerable: Direct search term reflection in HTML
            html.append("<h4>Search Results for: ").append(search).append("</h4>");
            html.append("<ul>")
                .append("<li>Customer A</li>")
                .append("<li>Customer B</li>")
                .append("</ul>");
        }

        return html.append("</body></html>").toString();
    }
}