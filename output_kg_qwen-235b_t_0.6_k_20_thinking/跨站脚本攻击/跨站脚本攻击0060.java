package com.example.xssdemo;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptServlet extends HttpServlet {
    private List<EncryptedFile> files = new ArrayList<>();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String action = request.getParameter("action");
        if ("upload".equals(action)) {
            String filename = request.getParameter("filename");
            String content = request.getParameter("content");
            
            // 模拟加密过程（真实场景中应有加密逻辑）
            String encrypted = Base64.getEncoder().encodeToString(content.getBytes());
            
            // 存储文件信息（存在漏洞：未对filename进行HTML转义）
            files.add(new EncryptedFile(filename, encrypted));
            response.sendRedirect("/xssdemo/list.jsp");
        }
    }
}

class EncryptedFile {
    private String filename;
    private String encryptedContent;

    public EncryptedFile(String filename, String encryptedContent) {
        this.filename = filename;
        this.encryptedContent = encryptedContent;
    }

    public String getFilename() { return filename; }
    public String getEncryptedContent() { return encryptedContent; }
}

// list.jsp
<%@ page import="com.example.xssdemo.*" %>
<%@ page import="java.util.*" %>
<html>
<head><title>Encrypted Files</title></head>
<body>
    <h2>Encrypted Files List</h2>
    <table border="1">
        <tr><th>Filename</th><th>Preview</th></tr>
        <% 
        List<EncryptedFile> files = ((FileEncryptServlet) application.getAttribute("fileServlet")).getFiles();
        for (EncryptedFile file : files) {
        %>
        <tr>
            <!-- 存在XSS漏洞：直接输出未经转义的文件名 -->
            <td><%= file.getFilename() %></td>
            <td><%= new String(Base64.getDecoder().decode(file.getEncryptedContent())).substring(0, 20) + "..." %></td>
        </tr>
        <% } %>
    </table>
</body>
</html>