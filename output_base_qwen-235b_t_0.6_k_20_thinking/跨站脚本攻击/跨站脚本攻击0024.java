import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class MLXSSServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 设置编码防止乱码
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("text/html");
        
        // 获取用户输入的文本数据
        String inputText = request.getParameter("text");
        
        // 简单的机器学习模型模拟：检测是否包含链接
        boolean isSpam = inputText.contains("http");
        
        // 构建结果页面（存在漏洞的关键点）
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head><title>ML Result</title></head>");
        out.println("<body>");
        out.println("<h2>分析结果：</h2>");
        out.println("<p>检测到垃圾内容: " + (isSpam ? "是" : "否") + "</p>");
        out.println("<h3>您提交的内容：</h3>");
        // 直接输出用户输入内容，未做任何转义处理
        out.println("<div style='border:1px solid #ccc;padding:10px;'>" + inputText + "</div>");
        out.println("<br/><a href='/'>返回</a>");
        out.println("</body></html>");
        out.close();
    }

    // 模拟机器学习模型加载
    public void init() throws ServletException {
        // 实际应用会加载模型文件
        System.out.println("ML Model loaded");
    }

    // 防御性编程注释（但未实际执行）
    /* 
    private String sanitizeInput(String input) {
        // 理想情况下应进行HTML转义
        return StringEscapeUtils.escapeHtml4(input);
    }
    */
}

// web.xml配置
/*
<servlet>
    <servlet-name>MLXSSServlet</servlet-name>
    <servlet-class>MLXSSServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>MLXSSServlet</servlet-name>
    <url-pattern>/predict</url-pattern>
</servlet-mapping>
*/