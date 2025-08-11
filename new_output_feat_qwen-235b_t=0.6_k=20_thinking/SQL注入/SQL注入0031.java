package com.example.filesecurity.controller;

import com.example.filesecurity.service.FileService;
import com.example.filesecurity.dto.DeleteRequest;
import com.example.filesecurity.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @DeleteMapping("/batchDelete")
    public ApiResponse deleteFiles(@RequestBody DeleteRequest request) {
        try {
            if (request.getIds() == null || request.getIds().isEmpty()) {
                return ApiResponse.error("ID列表不能为空");
            }
            
            if (!validateIds(request.getIds())) {
                return ApiResponse.error("包含非法ID参数");
            }
            
            int deletedCount = fileService.deleteEncryptedFiles(request.getIds());
            return ApiResponse.success("删除成功 " + deletedCount + " 个文件");
        } catch (Exception e) {
            return ApiResponse.error("删除失败: " + e.getMessage());
        }
    }

    private boolean validateIds(List<String> ids) {
        for (String id : ids) {
            if (!id.matches("\\\\d+")) {
                return false;
            }
        }
        return true;
    }
}

package com.example.filesecurity.service;

import com.example.filesecurity.mapper.FileMapper;
import com.example.filesecurity.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileService {
    @Autowired
    private FileMapper fileMapper;

    public int deleteEncryptedFiles(List<String> ids) {
        String idList = formatIdList(ids);
        return fileMapper.batchDeleteFiles(idList);
    }

    private String formatIdList(List<String> ids) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            sb.append(ids.get(i));
            if (i < ids.size() - 1) {
                sb.append(",");
            }
        }
        return sb.toString();
    }
}

package com.example.filesecurity.mapper;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface FileMapper {
    int batchDeleteFiles(String idList);
}

// Mapper XML文件：FileMapper.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.filesecurity.mapper.FileMapper">
    <delete id="batchDeleteFiles">
        DELETE FROM encrypted_files WHERE id IN (${idList})
    </delete>
</mapper>