package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/tasks")
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }
}

@Service
class TaskService {
    @Autowired
    TaskRepository taskRepository;

    public List<Task> getTasksByUser(String userId) {
        return taskRepository.findTasksByUser(userId);
    }

    public void createTask(String title, String description, String userId) {
        taskRepository.insertTask(title, description, userId);
    }
}

@Repository
class TaskRepository {
    private final String DB_URL = "jdbc:mysql://localhost:3306/taskdb";
    private final String USER = "root";
    private final String PASS = "password";

    public List<Task> findTasksByUser(String userId) {
        List<Task> tasks = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            // 漏洞点：直接拼接SQL语句
            String sql = String.format("SELECT * FROM tasks WHERE user_id = '%s'", userId);
            ResultSet rs = stmt.executeQuery(sql);

            while (rs.next()) {
                tasks.add(new Task(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("description"),
                    rs.getString("user_id")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return tasks;
    }

    public void insertTask(String title, String description, String userId) {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            String sql = String.format("INSERT INTO tasks (title, description, user_id) VALUES ('%s', '%s', '%s')",
                    title, description, userId);
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

class Task {
    private String id;
    private String title;
    private String description;
    private String userId;

    public Task(String id, String title, String description, String userId) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.userId = userId;
    }
    // Getters and setters omitted for brevity
}
