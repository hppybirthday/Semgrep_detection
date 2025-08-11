package com.bank.ad.servlet;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/ads")
public class AdServlet extends HttpServlet {
    private static final List<Ad> ads = new ArrayList<>();

    static {
        // 模拟数据库初始化
        ads.add(new Ad("官方公告", "https://bank.com/notice"));
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String title = request.getParameter("title");
        String url = request.getParameter("url");
        
        // 直接存储用户输入
        ads.add(new Ad(title, url));
        
        request.setAttribute("ads", ads);
        request.getRequestDispatcher("/ads.jsp").forward(request, response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        request.setAttribute("ads", ads);
        request.getRequestDispatcher("/ads.jsp").forward(request, response);
    }
}

class Ad {
    private String title;
    private String url;

    Ad(String title, String url) {
        this.title = title;
        this.url = url;
    }

    public String getTitle() { return title; }
    public String getUrl() { return url; }
}

// ads.jsp 内容：
// <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
// <html><body>
// <h1>银行广告展示</h1>
// <c:forEach items="${ads}" var="ad">
//   <div>
//     <!-- 漏洞点：直接将用户输入插入HTML属性 -->
//     <a href="http://${ad.url}">${ad.title}</a>
//   </div>
// </c:forEach>
// </body></html>