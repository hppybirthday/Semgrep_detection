package com.example.vulnerableapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/author")
public class AuthorServlet extends HttpServlet {
    private static Map<String, Author> authorDatabase = new HashMap<>();

    static {
        // 模拟数据库初始化
        authorDatabase.put("1", new Author("1", "John Doe"));
        authorDatabase.put("2", new Author("2", "Jane Smith"));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String authorId = request.getParameter("id");
        Author author = authorDatabase.get(authorId);
        
        if (author == null) {
            response.setContentType("text/html;charset=UTF-8");
            PrintWriter out = response.getWriter();
            // 漏洞点：直接将用户输入拼接到HTML响应中
            out.println("<div class='error'>Author not found: " + authorId + "</div>");
            return;
        }
        
        request.setAttribute("author", author);
        request.getRequestDispatcher("/WEB-INF/author.jsp").forward(request, response);
    }

    private static class Author {
        String id;
        String name;

        Author(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}

// WEB-INF/author.jsp 内容
// <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
// <html>
// <body>
//     <h1>Author Profile</h1>
//     <div>Name: ${author.name}</div>  <!-- 漏洞点：未转义输出 -->
// </body>
// </html>