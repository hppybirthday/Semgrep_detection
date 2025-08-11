package com.example.taskmanager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/tasks")
public class TaskServlet extends HttpServlet {
    private List<Task> taskList = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        String action = req.getParameter("action");
        if ("add".equals(action)) {
            String name = req.getParameter("name");
            String description = req.getParameter("description");
            taskList.add(new Task(name, description));
        }
        req.setAttribute("tasks", taskList);
        req.getRequestDispatcher("/taskList.jsp").forward(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        req.setAttribute("tasks", taskList);
        req.getRequestDispatcher("/taskList.jsp").forward(req, resp);
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

// taskList.jsp 内容（需放置在WEB-INF/jsp目录）:
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Tasks</title></head>
<body>
    <h1>Task List</h1>
    <form method="post">
        <input type="text" name="name" placeholder="Task name">
        <input type="text" name="description" placeholder="Description">
        <input type="hidden" name="action" value="add">
        <button type="submit">Add Task</button>
    </form>
    <ul>
        <% for (Task task : (List<Task>)request.getAttribute("tasks")) { %>
            <li>
                <strong><%= task.getName() %></strong>: 
                <%= task.getDescription() %>
            </li>
        <% } %>
    </ul>
</body>
</html>