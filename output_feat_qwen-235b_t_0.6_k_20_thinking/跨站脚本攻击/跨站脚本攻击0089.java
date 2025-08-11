package com.example.vulnerableapp;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@Controller
public class FileUploadController {
    // 模拟数据库存储
    private static final List<String> storedFilenames = new ArrayList<>();

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, Model model) {
        // 获取原始文件名（存在漏洞的关键点）
        String originalFilename = file.getOriginalFilename();
        
        // 直接存储用户输入的文件名到"数据库"
        if (originalFilename != null && !originalFilename.isEmpty()) {
            storedFilenames.add(originalFilename);
        }

        // 构建响应模型数据（直接传递原始文件名）
        model.addAttribute("filename", originalFilename);
        model.addAttribute("allFilenames", storedFilenames);
        
        // 返回包含XSS风险的视图
        return "fileUploadResult";
    }
}

// 前端Thymeleaf模板（fileUploadResult.html）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>File Upload Result</title></head>
// <body>
//     <h2>Uploaded File: <span th:text="${filename}"></span></h2>  // <!-- 直接渲染用户输入 -->
//     
//     <h3>All Uploaded Files:</h3>
//     <ul>
//         <li th:each="name : ${allFilenames}"
//             th:text="${name}">  // <!-- 直接渲染数据库存储的文件名 -->
//         </li>
//     </ul>
// </body>
// </html>