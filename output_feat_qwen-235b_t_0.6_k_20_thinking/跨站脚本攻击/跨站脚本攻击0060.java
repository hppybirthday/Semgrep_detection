import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class PostServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static List<Post> posts = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String title = request.getParameter("title");
        String content = request.getParameter("content");
        
        // 模拟存储到数据库（未进行任何输入验证）
        posts.add(new Post(title, content));
        
        response.sendRedirect("posts.jsp");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setAttribute("posts", posts);
        request.getRequestDispatcher("posts.jsp").forward(request, response);
    }

    static class Post {
        private String title;
        private String content;
        
        public Post(String title, String content) {
            this.title = title;
            this.content = content;
        }
        
        public String getTitle() { return title; }
        public String getContent() { return content; }
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>PostServlet</servlet-name>
    <servlet-class>PostServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>PostServlet</servlet-name>
    <url-pattern>/posts</url-pattern>
</servlet-mapping>
*/

// posts.jsp页面
/*
<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head><title>CRM Posts</title></head>
<body>
    <h2>User Posts</h2>
    
    <!-- 危险：直接输出用户输入的标题，未进行HTML转义 -->
    <c:forEach items="${posts}" var="post">
        <div style="border:1px solid #ccc; margin:10px; padding:10px;">
            <h3>${post.title}</h3>
            <p>${post.content}</p>
        </div>
    </c:forEach>
    
    <form action="posts" method="post">
        <input type="text" name="title" placeholder="Post Title" required>
        <textarea name="content" placeholder="Post Content" required></textarea>
        <button type="submit">Submit</button>
    </form>
</body>
</html>
*/