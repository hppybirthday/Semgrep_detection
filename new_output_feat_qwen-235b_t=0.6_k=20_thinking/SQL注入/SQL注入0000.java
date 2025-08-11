package com.securecryptool.controller;

import com.securecryptool.service.FileService;
import com.securecryptool.model.FileRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 文件管理控制器
 * 提供加密文件的查询接口
 */
@RestController
@RequestMapping("/api/files")
public class FileEncryptionController {
    @Autowired
    private FileService fileService;

    /**
     * 分页查询加密文件（存在SQL注入漏洞）
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @param sortBy 排序字段（存在注入点）
     * @return 文件列表
     */
    @GetMapping
    public ResponseEntity<?> listFiles(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortBy) {
        
        // 对sortBy参数进行看似合理的默认值处理（误导性代码）
        String sortColumn = (sortBy == null || sortBy.isEmpty()) 
            ? "create_time DESC" : sortBy;
            
        List<FileRecord> files = fileService.getFiles(pageNum, pageSize, sortColumn);
        return ResponseEntity.ok(files);
    }
}

package com.securecryptool.service;

import com.securecryptool.mapper.FileMapper;
import com.securecryptool.model.FileRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 文件业务逻辑层
 */
@Service
public class FileService {
    @Autowired
    private FileMapper fileMapper;

    /**
     * 获取加密文件列表
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @param sortColumn 排序字段（危险参数）
     * @return 文件列表
     */
    public List<FileRecord> getFiles(int pageNum, int pageSize, String sortColumn) {
        int offset = (pageNum - 1) * pageSize;
        // 调用Mapper执行存在漏洞的查询
        return fileMapper.selectFiles(pageSize, offset, sortColumn);
    }
}

package com.securecryptool.mapper;

import com.securecryptool.model.FileRecord;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * MyBatis Mapper接口（存在SQL注入漏洞）
 */
@Mapper
public interface FileMapper {
    /**
     * 动态SQL查询（存在漏洞）
     * 使用${}导致SQL注入（错误实践）
     */
    List<FileRecord> selectFiles(
        @Param("pageSize") int pageSize,
        @Param("offset") int offset,
        @Param("sortColumn") String sortColumn);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.securecryptool.mapper.FileMapper">
    <!-- 存在SQL注入的动态SQL -->
    <select id="selectFiles" resultType="com.securecryptool.model.FileRecord">
        SELECT *
        FROM encrypted_files
        ORDER BY ${sortColumn}  <!-- 危险的参数拼接 -->
        LIMIT #{pageSize} OFFSET #{offset}
    </select>
</mapper>