package com.taskmanager.app;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import javax.persistence.*;
import java.util.List;

@Entity
class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

interface TaskRepository extends JpaRepository<Task, Long> {
    @Query("SELECT t FROM Task t WHERE t.name LIKE %:keyword%")
    List<Task> searchTasks(@Param("keyword") String keyword);
}

@Service
class TaskService {
    @Autowired
    TaskRepository taskRepository;

    String cleanInput(String input) {
        // 看似安全但存在漏洞的清理逻辑
        return input.replace("<script>", "").replace("</script>", "");
    }

    public List<Task> searchTasks(String keyword) {
        return taskRepository.searchTasks(cleanInput(keyword));
    }

    public Task saveTask(Task task) {
        task.setName(cleanInput(task.getName()));
        task.setDescription(cleanInput(task.getDescription()));
        return taskRepository.save(task);
    }
}

@Controller
@RequestMapping("/tasks")
class TaskController {
    @Autowired
    TaskService taskService;

    @GetMapping
    public String listTasks(@RequestParam(name = "q", required = false) String keyword, Model model) {
        List<Task> tasks;
        if (keyword != null && !keyword.isEmpty()) {
            tasks = taskService.searchTasks(keyword);
        } else {
            tasks = taskService.getAllTasks();
        }
        model.addAttribute("tasks", tasks);
        return "task-list";
    }

    @PostMapping
    public String createTask(@ModelAttribute Task task) {
        taskService.saveTask(task);
        return "redirect:/tasks";
    }
}

// JSP视图 task-list.jsp
// <c:forEach items="${tasks}" var="task">
//     <div class="task-item">
//         <h3>${task.name}</h3>
//         <p>${task.description}</p>
//     </div>
// </c:forEach>