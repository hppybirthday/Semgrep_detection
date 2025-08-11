import java.util.*;

// 高抽象建模接口
interface Model {
    String getName();
    Map<String, Double> getParameters();
    void execute();
}

// 抽象模型基类
abstract class AbstractModel implements Model {
    protected String name;
    protected Map<String, Double> parameters = new HashMap<>();
    
    public String getName() {
        return name;
    }
    
    public Map<String, Double> getParameters() {
        return parameters;
    }
}

// 具体模型实现
class PolynomialModel extends AbstractModel {
    public PolynomialModel(String name) {
        this.name = name;
    }
    
    public void execute() {
        System.out.println("Executing polynomial simulation...");
    }
}

// 模型工厂
class ModelFactory {
    public static Model createModel(String type, String name) {
        switch(type) {
            case "polynomial":
                return new PolynomialModel(name);
            default:
                throw new IllegalArgumentException("Unknown model type");
        }
    }
}

// 报告生成器（漏洞所在）
class ReportGenerator {
    public String generateReport(Model model) {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>").append(model.getName()).append(" Report</title></head>"); // 漏洞点：未转义模型名称
        html.append("<body><h1>").append(model.getName()).append(" Simulation Results</h1>");
        html.append("<script>document.write('User session token: ' + document.cookie)</script>"); // 恶意脚本示例
        html.append("</body></html>");
        return html.toString();
    }
}

// 模型执行服务
class ModelingService {
    private ReportGenerator reportGenerator = new ReportGenerator();
    
    public String runModel(String modelType, String modelName) {
        Model model = ModelFactory.createModel(modelType, modelName);
        model.execute();
        return reportGenerator.generateReport(model);
    }
}

// 主程序
public class XSSDemo {
    public static void main(String[] args) {
        ModelingService service = new ModelingService();
        // 模拟用户输入（攻击者注入恶意名称）
        String evilName = "<script>alert('xss')</script>";
        String result = service.runModel("polynomial", evilName);
        System.out.println("Generated Report:\
" + result);
    }
}