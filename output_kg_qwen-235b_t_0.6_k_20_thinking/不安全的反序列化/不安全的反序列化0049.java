package com.example.taskmanager;

import java.io.*;
import java.util.*;
import java.util.Base64;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private List<Task> taskList = new ArrayList<>();

    @PostMapping("/deserialize")
    public String deserializeTask(@RequestParam String data) {
        try {
            // Vulnerable deserialization chain
            byte[] decoded = Base64.getDecoder().decode(data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
            Task task = (Task) ois.readObject();
            ois.close();
            
            // Business logic that encourages deserialization
            if (task.isValid() && !taskList.contains(task)) {
                taskList.add(task);
                return "Task added: " + task.getName();
            }
            return "Invalid task format";
            
        } catch (Exception e) {
            return "Deserialization failed: " + e.getMessage();
        }
    }
}

class Task implements Serializable {
    private String name;
    private boolean completed;
    private transient Runtime runtime = Runtime.getRuntime(); // Potential attack vector

    public Task(String name) {
        this.name = name;
    }

    // Business logic method that could be abused
    public boolean isValid() {
        return name != null && !name.trim().isEmpty();
    }

    // Getters and setters
    public String getName() { return name; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}