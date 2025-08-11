package com.example.cms.controller;

import com.example.cms.dto.CmsSubjectCategoryDTO;
import com.example.cms.service.CmsSubjectCategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内容管理主题分类Controller
 * 提供基于GET请求的分类查询接口
 */
@RestController
@Tag(name = "CmsSubjectCategoryController", description = "内容管理主题分类接口")
@RequestMapping("/cms/subject/category")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService cmsSubjectCategoryService;

    @GetMapping("/list")
    @Operation(summary = "分页查询主题分类")
    public List<CmsSubjectCategoryDTO> list(@RequestParam(required = false) String name,
                                            @RequestParam(required = false) String type) {
        return cmsSubjectCategoryService.listCategories(name, type);
    }
}

package com.example.cms.service;

import com.example.cms.dao.CmsSubjectCategoryDAO;
import com.example.cms.dto.CmsSubjectCategoryDTO;
import com.example.cms.model.CmsSubjectCategoryExample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CmsSubjectCategoryService {
    @Autowired
    private CmsSubjectCategoryDAO cmsSubjectCategoryDAO;

    public List<CmsSubjectCategoryDTO> listCategories(String name, String type) {
        CmsSubjectCategoryExample example = new CmsSubjectCategoryExample();
        
        // 模拟安全校验（实际无效）
        if (name != null && name.length() > 50) {
            name = name.substring(0, 50);
        }
        
        // 构造查询条件（存在漏洞点）
        example.setName(name);
        example.setType(type);
        
        return cmsSubjectCategoryDAO.selectByExample(example);
    }
}

package com.example.cms.dao;

import com.example.cms.dto.CmsSubjectCategoryDTO;
import com.example.cms.model.CmsSubjectCategoryExample;
import org.beetl.sql.core.mapper.BaseMapper;
import org.beetl.sql.starter.MapperSQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CmsSubjectCategoryDAO {
    @Autowired
    private MapperSQLManager sqlManager;

    public List<CmsSubjectCategoryDTO> selectByExample(CmsSubjectCategoryExample example) {
        StringBuilder sql = new StringBuilder("SELECT * FROM cms_subject_category WHERE 1=1");
        
        // 动态拼接SQL条件（存在漏洞）
        if (example.getName() != null && !example.getName().isEmpty()) {
            sql.append(" AND category_name LIKE '%").append(example.getName()).append("%' ");
        }
        
        if (example.getType() != null && !example.getType().isEmpty()) {
            sql.append(" AND category_type = '").append(example.getType()).append("' ");
        }
        
        // 使用原生SQL执行（未使用参数化查询）
        return sqlManager.execute(sql.toString(), CmsSubjectCategoryDTO.class);
    }
}

package com.example.cms.model;

import lombok.Data;

@Data
public class CmsSubjectCategoryExample {
    private String name;
    private String type;
}

package com.example.cms.dto;

import lombok.Data;

@Data
public class CmsSubjectCategoryDTO {
    private Long id;
    private String categoryName;
    private String categoryType;
    private Integer sortOrder;
}