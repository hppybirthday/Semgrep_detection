import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 高层抽象接口
typeface TaskRepository {
    List<Task> searchTasks(String title);
}

// 数据模型
class Task {
    private int id;
    private String title;
    private String description;
    // 省略getter/setter
}

// 数据访问实现
class JDBCTaskRepository implements TaskRepository {
    @Override
    public List<Task> searchTasks(String title) {
        List<Task> tasks = new ArrayList<>();
        try (Statement stmt = JDBCUtil.getConnection().createStatement()) {
            String sql = "SELECT * FROM tasks WHERE title LIKE '" + title + "'";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                Task task = new Task();
                task.setId(rs.getInt("id"));
                task.setTitle(rs.getString("title"));
                task.setDescription(rs.getString("description"));
                tasks.add(task);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database error", e);
        }
        return tasks;
    }
}

// 服务层
class TaskService {
    private TaskRepository repository;

    public TaskService(TaskRepository repository) {
        this.repository = repository;
    }

    public List<Task> findTasksByTitle(String title) {
        return repository.searchTasks("%" + title + "%");
    }
}

// 数据库连接工具类
class JDBCUtil {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("MySQL Driver not found", e);
        }
    }

    public static Connection getConnection() {
        try {
            return DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/taskdb", "user", "password");
        } catch (SQLException e) {
            throw new RuntimeException("Connection failed", e);
        }
    }
}

// 客户端代码
public class TaskManagerApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        TaskService service = new TaskService(new JDBCTaskRepository());

        System.out.println("Enter search term: ");
        String searchTerm = scanner.nextLine();
        
        // 存在漏洞的调用
        List<Task> results = service.findTasksByTitle(searchTerm);
        
        System.out.println("Found " + results.size() + " tasks:");
        results.forEach(task -> System.out.println(task.getTitle()));
    }
}