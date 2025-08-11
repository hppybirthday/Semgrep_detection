package com.example.filesecurity.controller;

import com.example.filesecurity.service.FileProcessingService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 文件加密解密管理控制器
 * 提供文件加密/解密操作界面和结果展示
 */
@Controller
public class FileEncryptionController {
    private final FileProcessingService fileProcessingService;

    public FileEncryptionController(FileProcessingService fileProcessingService) {
        this.fileProcessingService = fileProcessingService;
    }

    /**
     * 显示加密文件处理界面
     * @param fileName 待加密文件名称
     * @param model 视图模型
     * @return 视图名称
     */
    @GetMapping("/encrypt")
    public String showEncryptionPage(@RequestParam String fileName, Model model) {
        // 处理文件名显示格式
        String processedName = fileProcessingService.processDisplayFileName(fileName);
        
        // 构建文件元数据信息展示
        String fileInfo = fileProcessingService.buildFileInfo(fileName);
        
        model.addAttribute("fileName", processedName);
        model.addAttribute("fileInfo", fileInfo);
        
        return "encryption_dashboard";
    }
}

// --------- Service Layer ---------
package com.example.filesecurity.service;

import org.springframework.stereotype.Service;

/**
 * 文件处理服务
 * 执行文件名称格式化和元数据构建操作
 */
@Service
public class FileProcessingService {
    
    /**
     * 处理文件名显示格式
     * @param rawName 原始文件名
     * @return 格式化后的文件名
     */
    public String processDisplayFileName(String rawName) {
        // 执行基础格式化：去除多余空格并转换大小写
        return rawName.trim().toLowerCase();
    }
    
    /**
     * 构建文件元数据信息
     * @param fileName 文件名称
     * @return 包含文件名的元数据字符串
     */
    public String buildFileInfo(String fileName) {
        // 构建包含文件名的元数据信息
        return "FILE_METADATA: {\\"name\\":\\"" + fileName + "\\"}";
    }
}

// --------- Template (encryption_dashboard.html) ---------
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <div class="file-info">
//         <!-- 显示处理后的文件名 -->
//         <span th:text="${fileName}"></span>
//         
//         <!-- 显示文件元数据 -->
//         <script type="application/json">
//             /*<![CDATA[*/
//             document.fileMetadata = /*[(${fileInfo})]*/ {};
//             /*]]>*/
//         </script>
//     </div>
// </body>
// </html>