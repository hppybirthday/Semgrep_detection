package com.example.filesecurity.controller;

import com.example.filesecurity.service.FileEncryptionService;
import com.example.filesecurity.dto.FileSearchDTO;
import com.example.filesecurity.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileEncryptionController {
    @Autowired
    private FileEncryptionService fileEncryptionService;

    /**
     * 文件搜索接口
     * @param searchDTO 搜索条件
     * @return 加密文件列表
     */
    @PostMapping("/search")
    public ApiResponse<List<String>> searchFiles(@RequestBody FileSearchDTO searchDTO) {
        List<String> results = fileEncryptionService.searchEncryptedFiles(searchDTO);
        return ApiResponse.success(results);
    }
}

// ----------------------------------------

package com.example.filesecurity.service;

import com.example.filesecurity.mapper.FileSecurityMapper;
import com.example.filesecurity.dto.FileSearchDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FileEncryptionService {
    @Autowired
    private FileSecurityMapper fileSecurityMapper;

    public List<String> searchEncryptedFiles(FileSearchDTO searchDTO) {
        // 构造动态查询条件
        String queryCondition = buildQueryCondition(searchDTO);
        return fileSecurityMapper.searchFiles(queryCondition);
    }

    private String buildQueryCondition(FileSearchDTO searchDTO) {
        StringBuilder condition = new StringBuilder("1=1");
        
        if (searchDTO.getFileName() != null && !searchDTO.getFileName().isEmpty()) {
            condition.append(" AND file_name LIKE '%").append(searchDTO.getFileName()).append("%' ");
        }
        
        if (searchDTO.getSortField() != null && !searchDTO.getSortField().isEmpty()) {
            condition.append(" ORDER BY ").append(searchDTO.getSortField());
            
            if (searchDTO.getSortOrder() != null && !searchDTO.getSortOrder().isEmpty()) {
                condition.append(" ").append(searchDTO.getSortOrder());
            }
        }
        
        return condition.toString();
    }
}

// ----------------------------------------

package com.example.filesecurity.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FileSecurityMapper {
    @Select({"<script>",
      "SELECT encrypted_content FROM secure_files WHERE ${queryCondition}",
      "</script>"})
    List<String> searchFiles(@Param("queryCondition") String queryCondition);
}

// ----------------------------------------

package com.example.filesecurity.dto;

import lombok.Data;

@Data
public class FileSearchDTO {
    private String fileName;
    private String sortField;
    private String sortOrder;
}

// ----------------------------------------

package com.example.filesecurity.common;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(200);
        response.setMessage("Success");
        response.setData(data);
        return response;
    }
}