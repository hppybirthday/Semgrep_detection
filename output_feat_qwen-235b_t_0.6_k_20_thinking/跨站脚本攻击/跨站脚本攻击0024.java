import java.io.*;
import java.util.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.*;

@Controller
public class MLModelController {
    @PostMapping("/uploadDataset")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, Map<String, Object> model) {
        if (!file.isEmpty()) {
            try {
                // 模拟机器学习模型训练过程
                String result = trainModel(file);
                
                // 危险操作：直接将原始文件名插入HTML模板
                model.put("filename", file.getOriginalFilename());
                model.put("result", result);
                return "resultPage";
            } catch (Exception e) {
                // 错误信息直接暴露原始输入（二次漏洞点）
                model.put("error", "Failed to process file: " + file.getOriginalFilename());
                return "errorPage";
            }
        }
        return "redirect:/";
    }

    private String trainModel(MultipartFile file) {
        // 模拟模型训练过程
        // 实际业务中可能包含特征提取、模型推理等操作
        if (file.getOriginalFilename().contains("malicious")) {
            throw new RuntimeException("Attack pattern detected in " + file.getOriginalFilename());
        }
        return String.format("Model trained with %d features", file.getSize() % 100);
    }

    // 模拟前端模板引擎的渲染过程（漏洞核心）
    private String renderResultPage(Map<String, Object> model) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>").append("\
");
        html.append("<html>").append("\
");
        html.append("<head><title>ML Result</title></head>").append("\
");
        html.append("<body>").append("\
");
        html.append("<h1>Model Training Result</h1>").append("\
");
        html.append("<div class=\\"filename\\">Processed file: ").append(model.get("filename")).append("</div>").append("\
");
        html.append("<div class=\\"result\\">Training output: ").append(model.get("result")).append("</div>").append("\
");
        html.append("</body>").append("\
");
        html.append("</html>");
        return html.toString();
    }

    // 错误页面渲染时同样存在漏洞
    private String renderErrorPage(Map<String, Object> model) {
        return "<html><body><h1>Error</h1><div>" + model.get("error") + "</div></body></html>";
    }
}