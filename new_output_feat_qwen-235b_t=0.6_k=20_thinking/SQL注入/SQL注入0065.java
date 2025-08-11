package com.example.cms.controller;

import com.example.cms.dto.CmsSubjectCategoryDTO;
import com.example.cms.service.CmsSubjectCategoryService;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内容管理分类控制器
 * 提供基于MyBatis的动态SQL查询功能
 */
@RestController
@RequestMapping("/cms/subject/category")
@Api(tags = "CmsSubjectCategoryController", description = "内容分类管理")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService cmsSubjectCategoryService;

    @GetMapping("/list")
    @ApiOperation("分页查询分类列表")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "pageNum", value = "当前页码", required = true, dataType = "int"),
        @ApiImplicitParam(name = "pageSize", value = "每页数量", required = true, dataType = "int"),
        @ApiImplicitParam(name = "orderBy", value = "排序字段", dataType = "string")
    })
    public PageInfo<CmsSubjectCategoryDTO> list(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String orderBy) {
        
        // 模拟安全处理逻辑（实际存在绕过漏洞）
        if (orderBy != null && !orderBy.isEmpty()) {
            // 简单过滤尝试（可被绕过）
            orderBy = orderBy.replace("'", "");
            // 危险的排序拼接
            PageHelper.orderBy(orderBy); // 调用链最终触发SQL拼接
        }
        
        List<CmsSubjectCategoryDTO> categories = cmsSubjectCategoryService.selectAll();
        return new PageInfo<>(categories);
    }

    @DeleteMapping("/delete")
    @ApiOperation("批量删除分类")
    @ApiImplicitParam(name = "ids", value = "分类ID集合", required = true, dataType = "string")
    public int delete(@RequestParam String ids) {
        // 错误的参数处理方式
        String[] idArray = ids.split(",");
        StringBuilder safeIds = new StringBuilder();
        for (String id : idArray) {
            if (safeIds.length() > 0) safeIds.append(",");
            safeIds.append("'").append(id.replace("'", ""))
                    .append("'"); // 单引号过滤（可被宽字节绕过）
        }
        // 构造包含漏洞的查询条件
        return cmsSubjectCategoryService.deleteByCondition("id in (" + safeIds + ")");
    }
}

// Service层实现
package com.example.cms.service;

import com.example.cms.dto.CmsSubjectCategoryDTO;
import com.example.cms.mapper.CmsSubjectCategoryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CmsSubjectCategoryService {
    @Autowired
    private CmsSubjectCategoryMapper cmsSubjectCategoryMapper;

    public List<CmsSubjectCategoryDTO> selectAll() {
        return cmsSubjectCategoryMapper.selectByExample(null);
    }

    public int deleteByCondition(String condition) {
        return cmsSubjectCategoryMapper.deleteByExample(condition);
    }
}

// Mapper XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
    PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.cms.mapper.CmsSubjectCategoryMapper">
    <select id="selectByExample" resultType="com.example.cms.dto.CmsSubjectCategoryDTO">
        SELECT * FROM cms_subject_category
        <where>
            ${condition} <!-- 危险的条件拼接 -->
        </where>
        ORDER BY ${orderBy} <!-- 漏洞二次触发点 -->
    </select>

    <delete id="deleteByExample">
        DELETE FROM cms_subject_category
        <where>
            ${condition} <!-- 直接拼接导致注入 -->
        </where>
    </delete>
</mapper>