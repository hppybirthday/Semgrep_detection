package com.example.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Entity
class LogEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String message;
    
    public LogEntry() {}
    
    public LogEntry(String message) {
        this.message = message;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}

interface LogRepository extends JpaRepository<LogEntry, Long> {}

@Service
class LogService {
    @Autowired
    LogRepository logRepo;
    
    public void saveLog(String message) {
        logRepo.save(new LogEntry(message));
    }
    
    public List<LogEntry> getAllLogs() {
        return logRepo.findAll();
    }
}

@Controller
class LogController {
    @Autowired
    LogService logService;
    
    @GetMapping("/logs")
    public String viewLogs(Model model) {
        model.addAttribute("logs", logService.getAllLogs());
        return "logs";
    }
    
    @PostMapping("/logs")
    public String addLog(@RequestParam String message) {
        logService.saveLog(message);
        return "redirect:/logs";
    }
}

// logs.html (Thymeleaf template)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1>Job Logs</h1>
//     <div th:each="log : ${logs}">
//         <div>[[${log.message}]]</div>  // Vulnerable line
//     </div>
//     <form method="post" action="/logs">
//         <input type="text" name="message" />
//         <button type="submit">Submit</button>
//     </form>
// </body>
// </html>