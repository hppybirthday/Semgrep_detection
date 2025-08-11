import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

// 模拟任务实体
public class Task {
    private String title;
    private String description;
    
    public Task(String title, String description) {
        this.title = title;
        this.description = description;
    }
    
    public String getTitle() { return title; }
    public String getDescription() { return description; }
}

// 任务存储库
public class TaskRepository {
    private static List<Task> tasks = new ArrayList<>();
    
    public void addTask(Task task) {
        tasks.add(task);
    }
    
    public List<Task> getAllTasks() {
        return tasks;
    }
}

// 创建任务Servlet
@WebServlet("/createTask")
public class CreateTaskServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
            
        String title = request.getParameter("title");
        String description = request.getParameter("description");
        
        TaskRepository repo = new TaskRepository();
        repo.addTask(new Task(title, description));
        
        response.sendRedirect("viewTasks");
    }
}

// 查看任务Servlet
@WebServlet("/viewTasks")
public class ViewTasksServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
            
        request.setAttribute("tasks", new TaskRepository().getAllTasks());
        request.getRequestDispatcher("tasks.jsp").forward(request, response);
    }
}

// JSP页面(tasks.jsp)
/*
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>任务列表</title></head>
<body>
    <h1>所有任务</h1>
    <% for(Task task : (List<Task>)request.getAttribute("tasks")) { %>
        <div>
            <h3><%= task.getTitle() %></h3>
            <p><%= task.getDescription() %></p>
        </div>
    <% } %>
</body>
</html>
*/