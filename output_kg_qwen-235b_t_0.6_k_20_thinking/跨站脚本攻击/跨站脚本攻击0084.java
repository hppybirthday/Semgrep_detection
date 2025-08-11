package com.example.xss;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/comment")
public class CommentServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static List<String> comments = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户提交的评论内容
        String comment = request.getParameter("comment");
        
        // 数据清洗错误：未对输入内容进行HTML转义
        if (comment != null && !comment.isEmpty()) {
            // 直接存储原始输入内容
            comments.add(comment);
        }
        
        // 重定向到GET请求显示评论
        response.sendRedirect("comment");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        // 生成HTML页面头部
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head>");
        out.println("<meta charset=\\"UTF-8\\">");
        out.println("<title>用户评论</title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<h2>用户评论区</h2>");
        
        // 显示所有已存储的评论
        out.println("<div style=\\"margin:20px 0;\\">");
        out.println("<h3>已有评论：</h3>");
        if (comments.isEmpty()) {
            out.println("<p>暂无评论</p>");
        } else {
            for (String comment : comments) {
                // 漏洞点：直接输出未经转义的用户输入
                out.println("<div style=\\"border:1px solid #ccc; padding:10px; margin:5px 0;\\">");
                out.println(comment);  // 危险操作：直接输出用户输入内容
                out.println("</div>");
            }
        }
        out.println("</div>");
        
        // 生成评论提交表单
        out.println("<form method=\\"post\\" style=\\"margin:20px 0;\\">");
        out.println("<textarea name=\\"comment\\" rows=\\"4\\" cols=\\"50\\" required></textarea><br>");
        out.println("<input type=\\"submit\\" value=\\"提交评论\\">");
        out.println("</form>");
        
        out.println("</body>");
        out.println("</html>");
    }
}