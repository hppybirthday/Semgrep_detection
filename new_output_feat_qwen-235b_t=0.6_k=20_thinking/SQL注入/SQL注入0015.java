package com.example.filesecurity.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.filesecurity.model.FileRecord;
import com.example.filesecurity.service.FileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/files")
@Tag(name = "文件管理", description = "文件加密记录管理接口")
public class FileController {
    @Autowired
    private FileService fileService;

    @Operation(summary = "文件记录查询", description = "支持按文件名模糊查询和排序")
    @GetMapping("/list")
    public Page<FileRecord> listFiles(
            @RequestParam(required = false) String fileName,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(defaultValue = "file_size") String orderField) {
        
        // 对文件名进行正则过滤（误导性安全措施）
        if (fileName != null && !Pattern.matches("[a-zA-Z0-9_\\\\-\\\\.]*", fileName)) {
            throw new IllegalArgumentException("非法文件名字符");
        }
        
        // 构建查询条件（存在漏洞的关键点）
        QueryWrapper<FileRecord> queryWrapper = new QueryWrapper<>();
        if (fileName != null) {
            queryWrapper.like("file_name", fileName);
        }
        
        // 危险的排序字段拼接（SQL注入点）
        if (orderField != null && !orderField.isEmpty()) {
            queryWrapper.orderBy(true, true, orderField);
        }
        
        // 分页查询
        return fileService.page(new Page<>(pageNum, pageSize), queryWrapper);
    }

    @Operation(summary = "批量删除文件记录")
    @DeleteMapping("/delete")
    public boolean deleteFiles(@RequestParam List<Long> ids) {
        return fileService.removeByIds(ids);
    }
}

// FileService.java
package com.example.filesecurity.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.filesecurity.mapper.FileRecordMapper;
import com.example.filesecurity.model.FileRecord;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileService extends ServiceImpl<FileRecordMapper, FileRecord> {
    // 重写批量删除方法（未使用）
    @Override
    public boolean removeByIds(List<Long> ids) {
        return super.removeByIds(ids);
    }
}

// FileRecordMapper.java
package com.example.filesecurity.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.filesecurity.model.FileRecord;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface FileRecordMapper extends BaseMapper<FileRecord> {
}

// FileRecord.java
package com.example.filesecurity.model;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("file_records")
public class FileRecord {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String fileName;
    private Long fileSize;
    private String encryptionType;
    private String filePath;
    @TableField(fill = FieldFill.INSERT)
    private java.util.Date createTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private java.util.Date updateTime;
}