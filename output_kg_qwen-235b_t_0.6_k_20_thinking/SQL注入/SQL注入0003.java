package com.example.taskmanager;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 任务实体类
class Task {
    private int id;
    private String title;
    private String description;
    
    public Task(int id, String title, String description) {
        this.id = id;
        this.title = title;
        this.description = description;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// 数据访问层
class TaskDAO {
    private Connection connection;

    public TaskDAO() throws SQLException {
        // 模拟数据库连接
        this.connection = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/taskdb", "user", "password");
    }

    // 存在SQL注入漏洞的方法
    public List<Task> findTasksByTitle(String title) throws SQLException {
        List<Task> tasks = new ArrayList<>();
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT id, title, description FROM tasks WHERE title = '" 
                      + title + "'";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                tasks.add(new Task(
                    rs.getInt("id"),
                    rs.getString("title"),
                    rs.getString("description")
                ));
            }
        }
        return tasks;
    }

    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
}

// 服务层
class TaskService {
    private TaskDAO taskDAO;

    public TaskService() throws SQLException {
        taskDAO = new TaskDAO();
    }

    public List<Task> searchTasks(String title) throws SQLException {
        return taskDAO.findTasksByTitle(title);
    }
}

// 主程序
public class TaskManagerApp {
    public static void main(String[] args) {
        try {
            TaskService taskService = new TaskService();
            
            // 模拟用户输入（正常情况）
            System.out.println("正常查询测试：");
            List<Task> normalResults = taskService.searchTasks("Meeting");
            normalResults.forEach(task -> 
                System.out.println("ID: " + task.getId() + ", Title: " + task.getTitle())
            );
            
            // 模拟SQL注入攻击
            System.out.println("\
SQL注入测试（恶意输入）：");
            String maliciousInput = "" OR "1"="1";  // 恶意输入
            List<Task> attackResults = taskService.searchTasks(maliciousInput);
            attackResults.forEach(task -> 
                System.out.println("ID: " + task.getId() + ", Title: " + task.getTitle())
            );
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}