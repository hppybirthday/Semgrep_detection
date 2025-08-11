package com.example.mathsim.controller;

import com.example.mathsim.model.MathModel;
import com.example.mathsim.service.MathModelService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数学模型管理控制器
 * @author developer
 * @date 2023-10-15
 */
@Controller
@RequiredArgsConstructor
@RequestMapping("/models")
public class MathModelController {
    private final MathModelService mathModelService;

    /**
     * 创建数学模型
     * @param modelName 模型名称
     * @param parameters 模型参数（存在XSS漏洞）
     * @return 重定向到模型列表
     */
    @PostMapping
    public String createModel(@RequestParam String modelName, 
                             @RequestParam String parameters) {
        MathModel model = new MathModel();
        model.setModelName(modelName);
        model.setParameters(parameters);
        mathModelService.saveModel(model);
        return "redirect:/models/list";
    }

    /**
     * 显示模型详情
     * @param id 模型ID
     * @param model Spring MVC模型
     * @return 模型详情页面
     */
    @GetMapping("/{id}")
    public String viewModel(@PathVariable Long id, Model model) {
        MathModel storedModel = mathModelService.getModelById(id);
        if (storedModel != null) {
            model.addAttribute("modelName", storedModel.getModelName());
            model.addAttribute("parameters", storedModel.getParameters());
            // 漏洞点：直接传递原始参数值到前端
            model.addAttribute("rawParams", storedModel.getParameters());
        }
        return "model-detail";
    }

    /**
     * 模型列表展示
     */
    @GetMapping("/list")
    public String listModels(Model model) {
        List<MathModel> models = mathModelService.getAllModels();
        model.addAttribute("models", models);
        return "model-list";
    }

    /**
     * 漏洞利用辅助方法（模拟安全防护误导）
     * @param input 用户输入
     * @return 转义后的字符串
     */
    private String sanitizeInput(String input) {
        // 误导性安全措施：实际未被调用
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// -----------------------------------
// 服务层代码（简化）
package com.example.mathsim.service;

import com.example.mathsim.model.MathModel;
import com.example.mathsim.repository.MathModelRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MathModelService {
    private final MathModelRepository repository;

    public MathModelService(MathModelRepository repository) {
        this.repository = repository;
    }

    public void saveModel(MathModel model) {
        // 漏洞点：直接保存未经验证的输入
        repository.save(model);
    }

    public MathModel getModelById(Long id) {
        return repository.findById(id).orElse(null);
    }

    public List<MathModel> getAllModels() {
        return repository.findAll();
    }
}

// -----------------------------------
// Thymeleaf模板（model-detail.html）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>模型详情</title></head>
// <body>
//     <h1 th:text="${modelName}">模型名称</h1>
//     <div id="params">
//         <!-- 漏洞点：使用原始参数值生成HTML内容 -->
//         <script th:inline="javascript">
//             /*<![CDATA[*/
//             document.addEventListener('DOMContentLoaded', function() {
//                 var params = /*[(${rawParams})]*/ 'default';
//                 document.getElementById('params').innerHTML = params;
//             });
//             /*]]>*/
//         </script>
//     </div>
// </body>
// </html>