package com.secure.file.controller;

import com.secure.file.dto.FileQueryDTO;
import com.secure.file.service.FileService;
import com.secure.file.vo.FileVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 文件查询控制器
 * @author security team
 */
@RestController
@RequestMapping("/api/files")
@Tag(name = "文件查询", description = "用户收藏文件管理")
public class FileQueryController {
    @Autowired
    private FileService fileService;

    @GetMapping("/favorites")
    @Operation(summary = "查询收藏文件列表")
    public List<FileVO> getFavoriteFiles(
            @Parameter(description = "排序字段") @RequestParam(required = false) String sort,
            @Parameter(description = "排序方式") @RequestParam(required = false) String order,
            @Parameter(description = "当前页码") @RequestParam(defaultValue = "1") int pageNum) {
        FileQueryDTO queryDTO = new FileQueryDTO();
        queryDTO.setSortField(sort);
        queryDTO.setSortOrder(order);
        queryDTO.setPageNum(pageNum);
        return fileService.getFavoriteFiles(queryDTO);
    }
}

package com.secure.file.service;

import com.secure.file.dao.FileMapper;
import com.secure.file.dto.FileQueryDTO;
import com.secure.file.vo.FileVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 文件服务实现
 */
@Service
public class FileService {
    @Autowired
    private FileMapper fileMapper;

    public List<FileVO> getFavoriteFiles(FileQueryDTO queryDTO) {
        validateSortParams(queryDTO);
        return fileMapper.selectFavoriteFiles(queryDTO);
    }

    private void validateSortParams(FileQueryDTO dto) {
        if (dto.getSortField() != null && !dto.getSortField().matches("^[a-zA-Z0-9_\\\\.]+$")) {
            dto.setSortField(null);
            dto.setSortOrder(null);
        }
    }
}

package com.secure.file.dao;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.secure.file.vo.FileVO;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import java.util.List;

/**
 * 文件数据访问层
 */
public interface FileMapper extends BaseMapper<FileVO> {
    @SelectProvider(type = FileSqlProvider.class, method = "buildQuerySql")
    List<FileVO> selectFavoriteFiles(@Param("dto") Object queryDTO);
}

package com.secure.file.dao;

import org.apache.ibatis.jdbc.SQL;

/**
 * SQL构建类
 */
public class FileSqlProvider {
    public String buildQuerySql(Object dto) {
        // 反射获取参数值
        String sortField = getFieldValue(dto, "sortField");
        String sortOrder = getFieldValue(dto, "sortOrder");

        return new SQL() {{
            SELECT("*");
            FROM("favorite_files");
            ORDER_BY(String.format("%s %s", 
                sortField != null ? sortField : "create_time",
                sortOrder != null ? sortOrder : "desc"
            ));
        }}.toString();
    }

    private String getFieldValue(Object obj, String fieldName) {
        try {
            return (String) obj.getClass().getMethod("get" + capitalize(fieldName)).invoke(obj);
        } catch (Exception e) {
            return null;
        }
    }

    private String capitalize(String str) {
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }
}

package com.secure.file.dto;

import lombok.Data;

/**
 * 文件查询参数
 */
@Data
public class FileQueryDTO {
    private String sortField;
    private String sortOrder;
    private int pageNum;
}

package com.secure.file.vo;

import lombok.Data;

/**
 * 文件视图对象
 */
@Data
public class FileVO {
    private Long id;
    private String fileName;
    private String filePath;
    private String createTime;
}