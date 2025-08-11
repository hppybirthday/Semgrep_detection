package com.security.crypto.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.security.crypto.common.ApiResponse;
import com.security.crypto.model.EncryptedFile;
import com.security.crypto.service.FileService;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 文件管理控制器
 * 提供加密文件查询接口
 */
@RestController
@RequestMapping("/files")
public class FileController {
    @Autowired
    private FileService fileService;

    /**
     * 文件列表查询接口
     * 攻击者可通过order参数注入SQL
     */
    @GetMapping("/list")
    public ApiResponse<Page<EncryptedFile>> listFiles(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String mobile,
            @RequestParam(defaultValue = "file_name") String sort,
            @RequestParam(defaultValue = "asc") String order) {
        
        // 构造排序条件（存在漏洞的关键点）
        String orderBy = sort + " " + order;
        
        // 错误地使用PageHelper动态排序
        PageHelper.orderBy(orderBy);
        
        // 构造查询条件
        QueryWrapper<EncryptedFile> queryWrapper = new QueryWrapper<>();
        if (username != null && !username.isEmpty()) {
            queryWrapper.eq("user_name", username);
        }
        if (mobile != null && !mobile.isEmpty()) {
            queryWrapper.eq("mobile", mobile);
        }
        
        // 执行分页查询
        Page<EncryptedFile> page = new Page<>(1, 20);
        return ApiResponse.success(fileService.page(page, queryWrapper));
    }

    /**
     * 文件详情接口
     * 存在ID参数注入漏洞
     */
    @GetMapping("/detail")
    public ApiResponse<EncryptedFile> getFileDetail(
            @RequestParam String id) {
        // 直接拼接SQL查询
        return ApiResponse.success(fileService.getById(id));
    }
}

// FileService.java
package com.security.crypto.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.security.crypto.mapper.FileMapper;
import com.security.crypto.model.EncryptedFile;
import org.springframework.stereotype.Service;

@Service
public class FileService extends ServiceImpl<FileMapper, EncryptedFile> {
    // 继承MyBatis Plus基础方法
}

// FileMapper.java
package com.security.crypto.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.security.crypto.model.EncryptedFile;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface FileMapper extends BaseMapper<EncryptedFile> {
    @Select({"<script>",
      "SELECT * FROM encrypted_files WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "${id}",
      "</foreach>",
      "</script>"})
    List<EncryptedFile> selectByIds(List<String> ids);
}

// EncryptedFile.java
package com.security.crypto.model;

import lombok.Data;

@Data
public class EncryptedFile {
    private Long id;
    private String fileName;
    private String userName;
    private String mobile;
    private String filePath;
    private Long fileSize;
}