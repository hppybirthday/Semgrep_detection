package com.example.vulnerablecrawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class VulnerableCrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }
}

@Entity
class CrawlTask {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String taskName;
    @Lob
    private String htmlContent; // 存储爬取的原始HTML内容
    
    // Getters and setters
}

interface CrawlTaskRepository extends JpaRepository<CrawlTask, Long> {}

@Service
class CrawlService {
    private final CrawlTaskRepository repository;

    public CrawlService(CrawlTaskRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public void saveCrawledContent(String taskName, String rawHtml) {
        CrawlTask task = new CrawlTask();
        task.setTaskName(taskName);
        task.setHtmlContent(rawHtml); // 直接存储原始HTML
        repository.save(task);
    }

    public List<CrawlTask> getAllTasks() {
        return repository.findAll();
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    private final CrawlService crawlService;

    public TaskController(CrawlService crawlService) {
        this.crawlService = crawlService;
    }

    @PostMapping
    public String createTask(@RequestParam String name, @RequestParam String content) {
        crawlService.saveCrawledContent(name, content);
        return "redirect:/tasks/list";
    }

    @GetMapping("/list")
    public ModelAndView listTasks() {
        ModelAndView mv = new ModelAndView("task-list");
        mv.addObject("tasks", crawlService.getAllTasks());
        return mv;
    }
}

// templates/task-list.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <h1>Task List</h1>
//   <div th:each="task : ${tasks}">
//     <h3 th:text="${task.taskName}"></h3>
//     <div>Raw Content: <span th:utext="${task.htmlContent}"></span></div> <!-- 不安全的HTML渲染 -->
//   </div>
// </body>
// </html>