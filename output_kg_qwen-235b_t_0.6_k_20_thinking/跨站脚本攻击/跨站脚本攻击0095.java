package com.example.xssdemo;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.Base64;
import java.util.function.Function;

public class FileCryptServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    // 函数式编程风格的加密方法
    private static final Function<String, String> encryptor = data -> {
        return Base64.getEncoder().encodeToString(data.getBytes());
    };
    
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String plainText = request.getParameter("plaintext");
        String encrypted = encryptor.apply(plainText);
        
        // 存在漏洞：直接将用户输入传递给JSP页面
        request.setAttribute("plainText", plainText);
        request.setAttribute("encrypted", encrypted);
        request.getRequestDispatcher("/result.jsp").forward(request, response);
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.getWriter().println("<html><body>" + 
            "<form method='post'>" +
            "Text to encrypt: <input type='text' name='plaintext'/><br/>" +
            "<input type='submit' value='Encrypt'/>" +
            "</form></body></html>");
    }
}

// result.jsp
// 注意：未对用户输入进行HTML转义
/*
<html>
<head><title>Encrypted Result</title></head>
<body>
    <h2>Original Text: <%= request.getAttribute("plainText") %></h2>
    <h3>Encrypted Text: <%= request.getAttribute("encrypted") %></h3>
    <p>Copy your encrypted text to clipboard</p>
    <button onclick="navigator.clipboard.writeText('<%= request.getAttribute("encrypted") %>')">
        Copy Encrypted Text
    </button>
</body>
</html>
*/

// web.xml配置
/*
<servlet>
    <servlet-name>FileCryptServlet</servlet-name>
    <servlet-class>com.example.xssdemo.FileCryptServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>FileCryptServlet</servlet-name>
    <url-pattern>/crypt</url-pattern>
</servlet-mapping>
*/