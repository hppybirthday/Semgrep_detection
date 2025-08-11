import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

@WebServlet("/task")
public class TaskManager extends HttpServlet {
    private List<Task> tasks = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String description = request.getParameter("description");
        
        // 危险：直接存储未经验证的用户输入
        tasks.add(new Task(name, description));
        response.sendRedirect("/tasklist.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        request.setAttribute("tasks", tasks);
        try {
            getServletContext().getRequestDispatcher("/tasklist.jsp").forward(request, response);
        } catch (ServletException e) {
            e.printStackTrace();
        }
    }
}

class Task {
    private String name;
    private String description;

    public Task(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() { return name; }
    public String getDescription() { return description; }
}

// tasklist.jsp
// <%@ page contentType="text/html;charset=UTF-8" %>
// <html>
// <body>
// <h1>任务列表</h1>
// <% for(Task task : (List<Task>)request.getAttribute("tasks")) { %>
//   <div>
//     <!-- 危险：直接输出未经转义的用户输入 -->
//     <h3><%= task.getName() %></h3>
//     <p><%= task.getDescription() %></p>
//   </div>
// <% } %>
// </body>
// </html>