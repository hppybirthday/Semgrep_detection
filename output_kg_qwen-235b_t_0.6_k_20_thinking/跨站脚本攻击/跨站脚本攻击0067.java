import static spark.Spark.*;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class XSSVulnerableMLApp {
    // 模拟机器学习模型预测函数
    private static Function<String, String> mlModel = input -> {
        // 实际业务中可能是文本分类/情感分析模型
        // 此处简化为直接返回输入内容
        return "模型预测结果: " + input;
    };

    // 模拟HTML模板渲染（存在漏洞的关键点）
    private static Function<Map<String, String>, String> renderTemplate = (Map<String, String> context) -> {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h2>机器学习预测结果</h2>");
        html.append("<div id='result'>");
        html.append(context.get("prediction")); // 直接插入用户输入
        html.append("</div>");
        html.append("<form method='post'>");
        html.append("<textarea name='text'>");
        html.append(context.get("input"));
        html.append("</textarea>");
        html.append("<input type='submit' value='预测'>");
        html.append("</form></body></html>");
        return html.toString();
    };

    public static void main(String[] args) {
        port(8080);
        
        // POST处理函数式路由
        post("/predict", (req, res) -> {
            Map<String, String> context = new HashMap<>();
            String userInput = req.queryParams("text");
            
            // 直接使用用户输入进行预测（未过滤）
            String prediction = mlModel.apply(userInput);
            
            context.put("input", userInput);
            context.put("prediction", prediction);
            
            res.type("text/html");
            return renderTemplate.apply(context);
        });
        
        // GET处理函数式路由
        get("/", (req, res) -> {
            Map<String, String> context = new HashMap<>();
            context.put("input", "输入文本");
            context.put("prediction", "等待预测...");
            return renderTemplate.apply(context);
        });
    }
}
// 编译运行后访问 http://localhost:8080 测试漏洞
// 测试输入示例： <script>alert('xss')</script>