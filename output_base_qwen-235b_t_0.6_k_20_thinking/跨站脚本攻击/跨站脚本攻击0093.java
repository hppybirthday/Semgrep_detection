import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XSSVulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String initialValue = request.getParameter("initialValue");
        String timeSpan = request.getParameter("timeSpan");
        
        // 创建模型参数对象
        ModelParameters params = new ModelParameters(initialValue, timeSpan);
        
        // 验证参数（存在缺陷的验证）
        if(params.isValid()) {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("<html><body>");
            out.println("<h2>模型仿真结果</h2>");
            out.println("<p>初始值: " + params.getInitialValue() + "</p>");
            out.println("<p>时间跨度: " + params.getTimeSpan() + "</p>");
            out.println("<div id=\\"simulation\\">模拟数据: " + params.getInitialValue() * params.getTimeSpan() + "</div>");
            out.println("<script src=\\"/scripts/simulation.js\\"></script>");
            out.println("</body></html>");
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "参数无效");
        }
    }
}

class ModelParameters {
    private String initialValue;
    private String timeSpan;

    public ModelParameters(String initialValue, String timeSpan) {
        this.initialValue = initialValue;
        this.timeSpan = timeSpan;
    }

    public boolean isValid() {
        // 不充分的验证逻辑
        return initialValue != null && timeSpan != null;
    }

    public String getInitialValue() {
        return initialValue;
    }

    public String getTimeSpan() {
        return timeSpan;
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <servlet-class>XSSVulnerableServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>XSSVulnerableServlet</servlet-name>
    <url-pattern>/simulate</url-pattern>
</servlet-mapping>
*/