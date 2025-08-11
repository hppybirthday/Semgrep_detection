package com.enterprise.filemanager.controller;

import com.enterprise.filemanager.entity.FileEntity;
import com.enterprise.filemanager.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/files")
public class FileController {
    
    @Autowired
    private FileService fileService;

    @PostMapping("/upload")
    public ModelAndView handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (!file.isEmpty()) {
            try {
                String originalFilename = file.getOriginalFilename();
                FileEntity fileEntity = new FileEntity();
                fileEntity.setFileName(originalFilename);
                fileEntity.setFileSize(file.getSize());
                fileService.save(fileEntity);
            } catch (IOException e) {
                return new ModelAndView("error");
            }
        }
        return new ModelAndView("redirect:/files/list");
    }

    @GetMapping("/list")
    public ModelAndView listFiles() {
        List<FileEntity> files = fileService.getAll();
        ModelAndView modelAndView = new ModelAndView("fileList");
        modelAndView.addObject("files", files);
        return modelAndView;
    }
}

package com.enterprise.filemanager.service;

import com.enterprise.filemanager.entity.FileEntity;
import com.enterprise.filemanager.repository.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileService {
    
    @Autowired
    private FileRepository fileRepository;

    public void save(FileEntity file) {
        fileRepository.save(file);
    }

    public List<FileEntity> getAll() {
        return fileRepository.findAll();
    }
}

package com.enterprise.filemanager.template;

import com.enterprise.filemanager.entity.FileEntity;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class TemplateProcessor {
    
    public String processTemplate(List<FileEntity> files) {
        StringBuilder html = new StringBuilder("<ul class='file-list'>");
        for (FileEntity file : files) {
            html.append("<li>").append(file.getFileName()).append("</li>");
        }
        html.append("</ul>");
        return html.toString();
    }
}

package com.enterprise.filemanager.entity;

import lombok.Data;

import javax.persistence.*;

@Entity
@Table(name = "uploaded_files")
@Data
public class FileEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_name", nullable = false)
    private String fileName;

    @Column(name = "file_size")
    private Long fileSize;
}

package com.enterprise.filemanager.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Bean
    public XssSanitizer xssSanitizer() {
        return new XssSanitizer();
    }
}

package com.enterprise.filemanager.util;

import org.springframework.stereotype.Component;

@Component
public class XssSanitizer {
    
    public String sanitize(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>]", "");
    }
}