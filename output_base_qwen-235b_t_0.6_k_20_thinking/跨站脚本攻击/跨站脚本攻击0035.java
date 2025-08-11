import java.io.*;
import java.lang.reflect.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class TaskServlet extends HttpServlet {
    private class Task {
        public String title;
        public String description;
        public boolean completed;
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            Task task = new Task();
            Field[] fields = task.getClass().getDeclaredFields();
            
            for (Field field : fields) {
                String value = req.getParameter(field.getName());
                if (value != null) {
                    field.setAccessible(true);
                    field.set(task, value);
                }
            }
            
            resp.setContentType("text/html");
            PrintWriter out = resp.getWriter();
            out.println("<div class='task-details'>");
            out.println("<h2>Task Details</h2>");
            out.println("<p><b>Title:</b> " + task.title + "</p>");
            out.println("<p><b>Description:</b> " + task.description + "</p>");
            out.println("<p><b>Status:</b> " + (task.completed ? "Completed" : "Pending") + "</p>");
            out.println("<a href='/tasks'>Back to list</a>");
            out.println("</div>");
            
        } catch (IllegalAccessException | IllegalArgumentException | SecurityException e) {
            resp.sendError(500, "Internal Server Error");
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<form method='POST'>");
        out.println("Title: <input type='text' name='title'><br>");
        out.println("Description: <textarea name='description'></textarea><br>");
        out.println("<input type='checkbox' name='completed'> Completed<br>");
        out.println("<input type='submit' value='Create Task'>");
        out.println("</form>");
    }
}