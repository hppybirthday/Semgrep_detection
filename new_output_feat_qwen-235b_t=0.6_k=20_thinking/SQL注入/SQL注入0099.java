package com.example.entity;

import lombok.Data;

/**
 * 加密文件实体
 */
@Data
public class FileEncrypted {
    private Long id;
    private String fileName;
    private String encryptedData;
    private Integer status;
}

// ------------------------------------
package com.example.mapper;

import com.example.entity.FileEncrypted;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import java.util.List;

/**
 * 数据访问层接口
 */
public interface FileEncryptedMapper extends BaseMapper<FileEncrypted> {
    List<FileEncrypted> selectFiles(
        @Param("fileName") String fileName,
        @Param("status") Integer status,
        @Param("safeSortField") String safeSortField,
        @Param("safeSortOrder") String safeSortOrder);
}

// ------------------------------------
package com.example.service;

import com.example.entity.FileEncrypted;
import com.example.mapper.FileEncryptedMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * 业务逻辑层
 */
@Service
public class FileEncryptedService {
    @Autowired
    private FileEncryptedMapper fileEncryptedMapper;

    public List<FileEncrypted> getFiles(String fileName, Integer status, String sortField, String sortOrder) {
        // 模拟安全转义的误导性代码
        String safeField = SqlUtil.escapeOrderBySql(sortField);
        String safeOrder = SqlUtil.escapeOrderBySql(sortOrder);
        return fileEncryptedMapper.selectFiles(fileName, status, safeField, safeOrder);
    }
}

// ------------------------------------
package com.example.controller;

import com.example.entity.FileEncrypted;
import com.example.service.FileEncryptedService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

/**
 * 文件管理控制器
 */
@RestController
@RequestMapping("/files")
public class FileEncryptedController {
    @Autowired
    private FileEncryptedService fileEncryptedService;

    @GetMapping("/list")
    public List<FileEncrypted> listFiles(
        @RequestParam(required = false) String fileName,
        @RequestParam(required = false) Integer status,
        @RequestParam(required = false) String sortField,
        @RequestParam(required = false) String sortOrder) {
        return fileEncryptedService.getFiles(fileName, status, sortField, sortOrder);
    }
}

// ------------------------------------
package com.example.util;

/**
 * SQL工具类（存在缺陷的实现）
 */
public class SqlUtil {
    /**
     * 错误的转义逻辑：仅过滤引号
     */
    public static String escapeOrderBySql(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value.replaceAll("['"]", ""); // 仅移除引号
    }
}

// ------------------------------------
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mapper.FileEncryptedMapper">
    <select id="selectFiles" resultType="com.example.entity.FileEncrypted">
        SELECT * FROM encrypted_files
        <where>
            <if test="fileName != null and fileName != ''">
                AND file_name LIKE CONCAT('%', #{fileName}, '%')
            </if>
            <if test="status != null">
                AND status = #{status}
            </if>
        </where>
        <!-- 漏洞点：使用${}直接拼接排序参数 -->
        <if test="safeSortField != null and safeSortField != ''">
            ORDER BY ${safeSortField} ${safeSortOrder}
        </if>
    </select>
</mapper>