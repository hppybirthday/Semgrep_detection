package com.example.mathsim;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/simulate")
public class SimulationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    // 模拟数学模型元数据
    private class MathModel {
        String expression;
        String description;
        
        MathModel(String expr, String desc) {
            this.expression = expr;
            this.description = desc;
        }
    }
    
    // 不安全的模板引擎（元编程风格）
    private class TemplateEngine {
        String render(String template, Map<String, String> context) {
            String result = template;
            for (Map.Entry<String, String> entry : context.entrySet()) {
                // 直接替换导致XSS漏洞
                result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
            }
            return result;
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        // 获取用户输入（不进行任何验证）
        String expression = request.getParameter("expr");
        String description = request.getParameter("desc");
        
        // 构造数学模型
        MathModel model = new MathModel(
            expression != null ? expression : "sin(x)",
            description != null ? description : "Default function"
        );
        
        // 生成响应HTML
        TemplateEngine engine = new TemplateEngine();
        Map<String, String> context = new HashMap<>();
        context.put("expression", model.expression);
        context.put("description", model.description);
        
        // 不安全的HTML模板
        String template = "<!DOCTYPE html>\
" + 
            "<html>\
<head>\
    <title>Math Simulation</title>\
</head>\
<body>\
    <h1>Simulation Results</h1>\
    <div>\
        <p>Description: {{description}}</p>\
        <p>Expression: {{expression}}</p>\
        <!-- 模拟数学计算结果 -->\
        <div id=\\"result\\">Computed value: " + computeExpression(model.expression) + "</div>\
    </div>\
</body>\
</html>";

        // 发送响应
        response.setContentType("text/html");
        response.getWriter().write(engine.render(template, context));
    }
    
    // 模拟数学计算函数（不实际执行表达式）
    private String computeExpression(String expression) {
        // 实际应用中可能使用动态脚本执行
        // 这里仅模拟计算过程
        return "[SIMULATED_RESULT]";
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doGet(request, response);
    }
}