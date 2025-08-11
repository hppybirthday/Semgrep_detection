import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

// 高抽象建模的任务管理系统
public class TaskManagerServlet extends HttpServlet {
    private TaskService taskService = new TaskService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        String action = req.getParameter("action");
        if ("create".equals(action)) {
            String title = req.getParameter("title");
            String desc = req.getParameter("description");
            taskService.createTask(title, desc);
        }
        req.setAttribute("tasks", taskService.getAllTasks());
        req.getRequestDispatcher("/taskList.jsp").forward(req, res);
    }
}

class Task {
    private String title;
    private String description;
    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }
    // 模拟漏洞：直接返回原始输入
    public String getDisplayDescription() {
        return description; // 未转义输出
    }
}

class TaskService {
    private List<Task> tasks = new ArrayList<>();
    public void createTask(String title, String description) {
        tasks.add(new Task(title, description));
    }
    public List<Task> getAllTasks() {
        return tasks;
    }
}

// JSP页面(taskList.jsp)
// 模拟漏洞位置：
/*
<html>
<body>
    <h2>任务列表</h2>
    <ul>
    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
    <c:forEach items="${tasks}" var="task">
        <li>${task.displayDescription}</li>  // 未转义的危险输出
    </c:forEach>
    </ul>
</body>
</html>
*/