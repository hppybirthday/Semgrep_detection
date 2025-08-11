package com.example.cms.controller;

import com.example.cms.service.CmsSubjectCategoryService;
import com.example.common.result.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内容管理控制器
 * @author admin
 */
@RestController
@RequestMapping("/cms/subject/category")
@Tag(name = "CmsSubjectCategoryController", description = "内容分类管理")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService cmsSubjectCategoryService;

    @Operation(summary = "批量删除分类")
    @DeleteMapping("/delete")
    public Result<Boolean> deleteCategories(
            @Parameter(name = "ids", description = "分类ID列表")
            @RequestParam("ids") List<String> ids) {
        
        // 模拟业务校验
        if (ids == null || ids.isEmpty()) {
            return Result.fail("ID列表不能为空");
        }
        
        try {
            // 调用服务层处理删除
            boolean result = cmsSubjectCategoryService.batchDelete(ids);
            return Result.success(result);
        } catch (Exception e) {
            return Result.fail("删除失败: " + e.getMessage());
        }
    }
}

package com.example.cms.service;

import com.example.cms.mapper.CmsSubjectCategoryMapper;
import com.example.cms.model.CmsSubjectCategory;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 分类服务实现
 * @author admin
 */
@Service
public class CmsSubjectCategoryService extends ServiceImpl<CmsSubjectCategoryMapper, CmsSubjectCategory> {
    @Autowired
    private CmsSubjectCategoryMapper cmsSubjectCategoryMapper;

    /**
     * 批量删除分类（存在SQL注入漏洞）
     */
    public boolean batchDelete(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 构造SQL条件片段（危险操作）
        String sqlCondition = buildSqlCondition(ids);
        
        // 错误使用字符串拼接方式执行删除
        return cmsSubjectCategoryMapper.deleteByIds(sqlCondition);
    }
    
    /**
     * 构建SQL条件片段（看似安全的封装方法）
     */
    private String buildSqlCondition(List<String> ids) {
        // 模拟复杂的业务处理逻辑
        StringBuilder condition = new StringBuilder();
        condition.append("id in ('");
        
        // 错误的拼接逻辑（未处理恶意输入）
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) condition.append("','");
            condition.append(ids.get(i));
        }
        
        condition.append("')");
        return condition.toString();
    }
}

package com.example.cms.mapper;

import com.example.cms.model.CmsSubjectCategory;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

/**
 * 分类数据访问层
 * @author admin
 */
@Mapper
public interface CmsSubjectCategoryMapper extends BaseMapper<CmsSubjectCategory> {
    /**
     * 根据ID批量删除（存在SQL注入漏洞）
     * @param condition SQL条件片段
     */
    @Delete({"<script>",
             "DELETE FROM cms_subject_category WHERE ${condition}",
             "</script>"})
    boolean deleteByIds(String condition);
}

package com.example.cms.model;

import com.baomidou.mybatisplus.annotation.*;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * 内容分类实体
 * @author admin
 */
@Data
@TableName("cms_subject_category")
@Schema(description = "内容分类实体")
public class CmsSubjectCategory {
    @Schema(description = "分类ID")
    @TableId(type = IdType.AUTO)
    private Long id;

    @Schema(description = "分类名称")
    @TableField("name")
    private String name;

    @Schema(description = "排序字段")
    @TableField("sort")
    private Integer sort;

    @Schema(description = "是否启用")
    @TableField("enabled")
    private Boolean enabled;
}