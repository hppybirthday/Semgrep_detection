package com.taskmanager.domain;

import java.util.List;
import java.util.ArrayList;
import java.sql.*;

// 实体类
public class Task {
    private String id;
    private String title;
    private String description;
    private String status;
    // 省略getter/setter
}

// 仓储接口
interface TaskRepository {
    List<Task> findTasksByTitle(String title) throws SQLException;
}

// 漏洞实现类
class JdbcTaskRepository implements TaskRepository {
    private Connection connection;

    public JdbcTaskRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public List<Task> findTasksByTitle(String title) throws SQLException {
        List<Task> result = new ArrayList<>();
        // 漏洞点：直接拼接SQL字符串
        String query = "SELECT * FROM tasks WHERE title LIKE '%" + title + "%'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        while (rs.next()) {
            Task task = new Task();
            task.setId(rs.getString("id"));
            task.setTitle(rs.getString("title"));
            task.setDescription(rs.getString("description"));
            task.setStatus(rs.getString("status"));
            result.add(task);
        }
        return result;
    }
}

// 领域服务
class TaskService {
    private TaskRepository repository;

    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }

    public List<Task> searchTasks(String keyword) throws SQLException {
        return repository.findTasksByTitle(keyword);
    }
}

// 控制器层
class TaskController {
    private TaskService taskService;

    public TaskController(TaskService taskService) {
        this.taskService = taskService;
    }

    public void handleSearch(String userInput) {
        try {
            List<Task> tasks = taskService.searchTasks(userInput);
            System.out.println("Found " + tasks.size() + " tasks");
        } catch (Exception e) {
            System.err.println("Query failed: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 模拟用户输入
        String maliciousInput = "task' OR '1'='1";
        
        // 初始化各层组件
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "user", "password");
            TaskRepository repo = new JdbcTaskRepository(conn);
            TaskService service = new TaskService(repo);
            TaskController controller = new TaskController(service);
            
            // 触发漏洞
            controller.handleSearch(maliciousInput);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}