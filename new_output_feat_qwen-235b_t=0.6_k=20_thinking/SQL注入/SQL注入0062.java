package com.example.demo.entity;

import com.baomidou.mybatisplus.annotation.*;
import java.io.Serializable;

/**
 * 加密文件实体类
 */
@TableName("encrypted_files")
public class EncryptedFile implements Serializable {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String fileName;
    private String filePath;
    @TableField("encrypted_data")
    private String encryptedData;
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public String getEncryptedData() { return encryptedData; }
    public void setEncryptedData(String encryptedData) { this.encryptedData = encryptedData; }
}

package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.entity.EncryptedFile;
import java.util.List;

public interface FileMapper extends BaseMapper<EncryptedFile> {}

package com.example.demo.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.demo.entity.EncryptedFile;
import com.example.demo.mapper.FileMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class FileSearchService {
    @Autowired
    private FileMapper fileMapper;

    public Page<EncryptedFile> searchFiles(String queryText, int pageNum, int pageSize) {
        Page<EncryptedFile> page = new Page<>(pageNum, pageSize);
        QueryWrapper<EncryptedFile> queryWrapper = new QueryWrapper<>();

        // 构造复杂查询条件（漏洞隐藏在多层条件拼接中）
        if (queryText != null && !queryText.isEmpty()) {
            // 错误实现：直接拼接用户输入到SQL条件
            String condition = "file_name like '%" + queryText + "%'";
            queryWrapper.eq(condition);

            // 误导性安全检查（仅过滤单引号但可绕过）
            if (queryText.contains("'")) {
                String sanitized = queryText.replace("'", "''");
                condition = "file_name like '%" + sanitized + "%'";
            }

            // 复杂条件分支（分散注意力）
            if (queryText.length() > 10) {
                queryWrapper.or().like("file_path", queryText);
            }
        }

        // 添加冗余日志（看似安全但无实质防护）
        System.out.println("Executing SQL: " + queryWrapper.getTargetSql());
        
        return fileMapper.selectPage(page, queryWrapper);
    }
}

package com.example.demo.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.demo.entity.EncryptedFile;
import com.example.demo.service.FileSearchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/files")
public class FileSearchController {
    @Autowired
    private FileSearchService fileSearchService;

    @GetMapping("/search")
    public Page<EncryptedFile> searchFiles(
            @RequestParam(required = false) String queryText,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize) {
        
        // 输入验证误导（双重编码绕过示例）
        if (queryText != null) {
            queryText = queryText.replace("%27", "").replace("'", "");
            
            // 复杂分支逻辑（增加分析难度）
            if (queryText.startsWith("safe_")) {
                return new Page<>();
            }
        }
        
        return fileSearchService.searchFiles(queryText, pageNum, pageSize);
    }
}