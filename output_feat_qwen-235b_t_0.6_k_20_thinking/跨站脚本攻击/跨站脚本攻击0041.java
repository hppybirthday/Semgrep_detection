package com.example.demo.controller;

import com.example.demo.dto.MinioUploadDto;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@Controller
public class SearchController {
    private List<String> searchHistory = new ArrayList<>();

    @GetMapping("/search")
    public String search(@RequestParam("keyword") String keyword, Model model) {
        // 模拟大数据处理：存储搜索记录
        searchHistory.add(keyword);
        
        // 漏洞点：未转义用户输入直接绑定到模板
        MinioUploadDto dto = new MinioUploadDto();
        dto.setFileName(keyword);
        
        model.addAttribute("searchKeyword", keyword);
        model.addAttribute("uploadDto", dto);
        model.addAttribute("history", searchHistory);
        
        return "searchResults";
    }

    @ModelAttribute("uploadDto")
    public MinioUploadDto getUploadDto() {
        return new MinioUploadDto();
    }
}

// DTO类
package com.example.demo.dto;

public class MinioUploadDto {
    private String fileName;
    
    // 漏洞点：无转义处理的getter
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
}

// Thymeleaf模板（searchResults.html）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h2>搜索结果：[[${searchKeyword}]]</h2> <!-- 漏洞点1：不安全的表达式 -->
//     <p>当前文件名：<input type="text" value="[[${uploadDto.fileName}]]" /> <!-- 漏洞点2：反射型XSS --></p>
//     <div th:each="item : ${history}">
//         <a th:href="|/search?keyword=${item}|" th:text="${item}"></a> <!-- 漏洞点3：存储型XSS -->
//     </div>
// </body>
// </html>