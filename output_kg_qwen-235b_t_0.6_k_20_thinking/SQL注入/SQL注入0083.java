import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 任务实体类
class Task {
    private int id;
    private String name;
    private String description;

    // 构造方法/getter/setter
    public Task(int id, String name, String description) {
        this.id = id;
        this.name = name;
        this.description = description;
    }

    @Override
    public String toString() {
        return "Task{ID=" + id + ", 名称='" + name + '\\'', 内容='" + description + '\\'' + '}';
    }
}

// 数据访问层
class TaskDAO {
    private Connection connection;

    public TaskDAO(Connection conn) {
        this.connection = conn;
    }

    // 存在漏洞的查询方法
    public List<Task> findTaskByName(String taskName) throws SQLException {
        List<Task> tasks = new ArrayList<>();
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM tasks WHERE name = '" + taskName + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            tasks.add(new Task(
                rs.getInt("id"),
                rs.getString("name"),
                rs.getString("description")
            ));
        }
        return tasks;
    }

    // 初始化数据库表
    public void initSchema() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS tasks (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100), description TEXT)");
        // 插入测试数据
        stmt.execute("INSERT INTO tasks (name, description) VALUES ('测试任务1', '初始测试数据')");
    }
}

// 业务逻辑层
class TaskService {
    private TaskDAO taskDAO;

    public TaskService(TaskDAO dao) {
        this.taskDAO = dao;
    }

    public List<Task> searchTasks(String userInput) throws SQLException {
        // 直接传递用户输入到DAO层
        return taskDAO.findTaskByName(userInput);
    }
}

public class Main {
    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "password");
            TaskDAO dao = new TaskDAO(conn);
            dao.initSchema();
            TaskService service = new TaskService(dao);

            // 模拟用户输入
            Scanner scanner = new Scanner(System.in);
            System.out.println("请输入任务名称进行搜索（可尝试注入）:");
            String userInput = scanner.nextLine();

            // 执行查询
            List<Task> result = service.searchTasks(userInput);
            System.out.println("查询结果:");
            result.forEach(System.out::println);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}