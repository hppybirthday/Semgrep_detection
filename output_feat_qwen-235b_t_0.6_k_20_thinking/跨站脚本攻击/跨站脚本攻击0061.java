import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

@Controller
public class MathModelController {
    
    @GetMapping("/modelForm")
    public String showForm(Model model) {
        model.addAttribute("mathModel", new MathModel());
        return "modelForm";
    }
    
    @PostMapping("/submitModel")
    public String processForm(@ModelAttribute MathModel model, Model m) {
        // 漏洞点：直接将用户输入的模型名称拼接到HTML字符串中
        String resultHtml = "<div class='result'>\
" +
                          "  <h2>" + model.getModelName() + "</h2>\
" +
                          "  <p>参数值: " + model.getParameters() + "</p>\
" +
                          "</div>";
        
        // 模拟存储到共享存储空间
        ModelRepository.addModelResult(resultHtml);
        m.addAttribute("results", ModelRepository.getAllResults());
        return "modelResults";
    }
    
    // 模拟数据模型类
    public static class MathModel {
        private String modelName;
        private String parameters;
        
        // Getters and setters
        public String getModelName() { return modelName; }
        public void setModelName(String name) { this.modelName = name; }
        
        public String getParameters() { return parameters; }
        public void setParameters(String params) { this.parameters = params; }
    }
    
    // 模拟存储库
    public static class ModelRepository {
        private static StringBuilder results = new StringBuilder();
        
        public static void addModelResult(String html) {
            results.append(html);
        }
        
        public static String getAllResults() {
            return results.toString();
        }
    }
}