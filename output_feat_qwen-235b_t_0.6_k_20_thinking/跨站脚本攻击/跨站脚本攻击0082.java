import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 任务实体类
public class Task {
    private int id;
    private String description;
    private String triggerMsg;
    private String handleMsg;

    // 构造方法
    public Task(String description, String triggerMsg, String handleMsg) {
        this.description = description;
        this.triggerMsg = triggerMsg;
        this.handleMsg = handleMsg;
    }

    // Getter方法
    public String getDescription() { return description; }
    public String getTriggerMsg() { return triggerMsg; }
    public String getHandleMsg() { return handleMsg; }
}

// 数据访问层
class TaskDAO {
    private Connection connection;

    public TaskDAO() {
        try {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/taskdb", "user", "pass");
        } catch (SQLException e) { e.printStackTrace(); }
    }

    public void saveTask(Task task) {
        String sql = "INSERT INTO tasks(description, trigger_msg, handle_msg) VALUES(?,?,?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, task.getDescription());
            stmt.setString(2, task.getTriggerMsg());
            stmt.setString(3, task.getHandleMsg());
            stmt.executeUpdate();
        } catch (SQLException e) { e.printStackTrace(); }
    }
}

// 控制器
@WebServlet("/addTask")
public class TaskServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String description = request.getParameter("description");
        String triggerMsg = request.getParameter("triggerMsg");
        String handleMsg = request.getParameter("handleMsg");
        
        Task task = new Task(description, triggerMsg, handleMsg);
        new TaskDAO().saveTask(task);
        
        response.sendRedirect("taskDetails.jsp?id=" + task.getId());
    }
}

// JSP显示页面（taskDetails.jsp）
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Task Details</title></head>
<body>
    <h1>Task Description: <%= task.getDescription() %></h1>
    <p>Trigger Message: <%= task.getTriggerMsg() %></p>
    <p>Handle Message: <%= task.getHandleMsg() %></p>
</body>
</html>