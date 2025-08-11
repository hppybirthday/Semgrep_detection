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
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

@WebServlet("/guestbook")
public class GuestbookServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<String> comments = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String comment = request.getParameter("comment");
        if (comment != null && !comment.trim().isEmpty()) {
            // 使用不安全的清理策略：允许基本HTML但未过滤javascript协议
            String safeComment = Jsoup.clean(comment, Safelist.basic());
            comments.add(safeComment);
        }
        response.sendRedirect("guestbook");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><head><title>Guestbook</title></head><body>");
        out.println("<h1>Guestbook</h1>");
        out.println("<form method='post'>");
        out.println("Comment: <input type='text' name='comment'><br>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form>");
        out.println("<h2>Comments:</h2>");
        for (String comment : comments) {
            // 直接输出用户输入内容导致XSS
            out.println("<div>" + comment + "</div>");
        }
        out.println("</body></html>");
    }
}