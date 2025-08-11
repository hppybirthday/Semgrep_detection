package com.taskmanager.domain;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 实体类
public class Task {
    private String id;
    private String name;
    private String description;
    private boolean completed;
    // 省略getter/setter

    public Task(String id, String name, String description) {
        this.id = id;
        this.name = name;
        this.description = description;
    }
}

// 仓储接口
interface TaskRepository {
    List<Task> findTasks(String taskName) throws SQLException;
}

// 数据库实现
class JDBCTaskRepository implements TaskRepository {
    private Connection connection;

    public JDBCTaskRepository() throws SQLException {
        this.connection = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/taskdb", "user", "pass");
    }

    @Override
    public List<Task> findTasks(String taskName) throws SQLException {
        Statement stmt = connection.createStatement();
        // 漏洞点：直接拼接SQL
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM tasks WHERE name LIKE '%" + taskName + "%'" );

        List<Task> tasks = new ArrayList<>();
        while (rs.next()) {
            tasks.add(new Task(
                rs.getString("id"),
                rs.getString("name"),
                rs.getString("description")
            ));
        }
        return tasks;
    }
}

// 领域服务
class TaskService {
    private TaskRepository taskRepo;

    public TaskService(TaskRepository repo) {
        this.taskRepo = repo;
    }

    public List<Task> searchTasks(String query) throws SQLException {
        return taskRepo.findTasks(query);
    }
}