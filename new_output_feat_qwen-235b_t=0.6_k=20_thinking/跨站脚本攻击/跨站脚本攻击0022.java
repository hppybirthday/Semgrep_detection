package com.example.mlplatform.controller;

import com.example.mlplatform.model.FileEntity;
import com.example.mlplatform.service.FileStorageService;
import com.example.mlplatform.service.ModelTrainingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.List;

/**
 * @author ml-developer
 * @date 2023-10-15
 */
@Controller
@RequestMapping("/model")
public class ModelTrainingController {
    
    @Autowired
    private FileStorageService fileStorageService;
    
    @Autowired
    private ModelTrainingService modelTrainingService;
    
    /**
     * 显示模型训练页面
     */
    @GetMapping("/train")
    public String showTrainingPage(Model model) {
        List<FileEntity> datasets = fileStorageService.getAllDatasets();
        model.addAttribute("datasets", datasets);
        return "train-model";
    }
    
    /**
     * 处理模型训练请求
     */
    @PostMapping("/train")
    public ModelAndView handleModelTraining(@RequestParam("dataset") String datasetId,
                                           @RequestParam("modelName") String modelName) {
        ModelAndView modelAndView = new ModelAndView("training-result");
        
        try {
            // 模拟模型训练过程
            String trainingResult = modelTrainingService.trainModel(datasetId, modelName);
            modelAndView.addObject("result", trainingResult);
            
        } catch (Exception e) {
            modelAndView.addObject("error", "模型训练失败: " + e.getMessage());
        }
        
        return modelAndView;
    }
    
    /**
     * 处理文件上传
     */
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                Model model) {
        if (file.isEmpty()) {
            model.addAttribute("error", "请选择要上传的文件");
            return "upload-error";
        }
        
        try {
            // 危险操作：直接使用原始文件名存储
            String originalFilename = file.getOriginalFilename();
            FileEntity fileEntity = new FileEntity();
            fileEntity.setName(originalFilename);
            fileEntity.setPath("/data/datasets/" + System.currentTimeMillis() + "_" + originalFilename);
            
            // 存储文件元数据到数据库
            fileStorageService.saveDatasetMetadata(fileEntity);
            
            // 实际文件存储操作（模拟）
            fileStorageService.storeFile(file, fileEntity.getPath());
            
            model.addAttribute("success", "文件上传成功: " + originalFilename);
            
        } catch (IOException e) {
            model.addAttribute("error", "文件上传失败: " + e.getMessage());
        }
        
        return "upload-result";
    }
}

// Thymeleaf模板 train-model.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>模型训练</title></head>
// <body>
//     <h1>选择训练数据集</h1>
//     <form th:action="@{/model/train}" method="post">
//         <select name="dataset">
//             <option th:each="dataset : ${datasets}"
//                     th:value="${dataset.id}"
//                     th:text="${dataset.name}">Dataset Name</option>
//         </select>
//         <input type="text" name="modelName">
//         <button type="submit">开始训练</button>
//     </form>
// </body>
// </html>