package com.example.xssdemo;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.*;
import java.nio.file.Paths;
import java.util.Base64;

@MultipartConfig
public class FileEncryptServlet extends HttpServlet {
    private String encrypt(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    private String decrypt(String data) {
        return new String(Base64.getDecoder().decode(data));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String action = request.getParameter("action");
        String userInputFileName = request.getParameter("fileName");
        Part filePart = request.getPart("file");
        String uploadedFileName = null;
        String fileContent = null;

        if (filePart != null) {
            uploadedFileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
            try (InputStream is = filePart.getInputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                StringBuilder contentBuilder = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    contentBuilder.append(line);
                }
                fileContent = contentBuilder.toString();
            }
        }

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        out.println("<html><body>");
        out.println("<h2>文件加密解密工具</h2>");

        try {
            if ("encrypt".equals(action)) {
                String encryptedContent = encrypt(fileContent);
                String encryptedFileName = "encrypted_" + (userInputFileName != null ? userInputFileName : uploadedFileName);

                out.println("文件名: " + uploadedFileName + "<br>");
                out.println("用户输入的文件名: " + userInputFileName + "<br>");
                out.println("加密后的文件名: " + encryptedFileName + "<br>");
                out.println("加密内容预览: " + encryptedContent.substring(0, Math.min(100, encryptedContent.length())) + "...<br>");
                out.println("<script>alert('加密完成');</script>");

            } else if ("decrypt".equals(action)) {
                String decryptedContent = decrypt(fileContent);
                out.println("文件名: " + uploadedFileName + "<br>");
                out.println("解密内容预览: " + decryptedContent.substring(0, Math.min(100, decryptedContent.length())) + "...<br>");
            } else {
                out.println("错误：未知的操作类型<br>");
            }
        } catch (Exception e) {
            out.println("处理过程中发生错误: " + e.getMessage() + "<br>");
        }

        out.println("<a href=\\"/encryptor\\">返回</a>");
        out.println("</body></html>");
        out.close();
    }

    @Override
    public void init() throws ServletException {
        System.out.println("文件加密服务启动");
    }
}