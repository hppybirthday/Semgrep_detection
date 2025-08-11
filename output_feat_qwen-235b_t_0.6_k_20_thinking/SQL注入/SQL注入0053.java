package com.example.demo.controller;

import com.example.demo.service.CmsSubjectCategoryService;
import com.example.demo.entity.CmsSubjectCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/cms/subject/category")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService cmsSubjectCategoryService;

    @GetMapping("/list")
    public List<CmsSubjectCategory> listCategories(HttpServletRequest request) {
        String orderBy = request.getParameter("orderBy");
        return cmsSubjectCategoryService.getCategories(orderBy);
    }
}

package com.example.demo.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.demo.entity.CmsSubjectCategory;
import com.example.demo.mapper.CmsSubjectCategoryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CmsSubjectCategoryService {
    @Autowired
    private CmsSubjectCategoryMapper cmsSubjectCategoryMapper;

    public List<CmsSubjectCategory> getCategories(String orderBy) {
        QueryWrapper<CmsSubjectCategory> queryWrapper = new QueryWrapper<>();
        // SQL注入漏洞点：直接拼接ORDER BY子句
        if (orderBy != null && !orderBy.isEmpty()) {
            queryWrapper.orderBy(true, true, "ORDER BY " + orderBy);
        }
        return cmsSubjectCategoryMapper.selectList(queryWrapper);
    }
}

package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.entity.CmsSubjectCategory;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CmsSubjectCategoryMapper extends BaseMapper<CmsSubjectCategory> {
}

package com.example.demo.entity;

import lombok.Data;

@Data
public class CmsSubjectCategory {
    private Long id;
    private String categoryName;
    private Integer sort;
    private Integer showStatus;
}

// MyBatis XML映射文件（实际路径/resources/mapper/CmsSubjectCategoryMapper.xml）
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.mapper.CmsSubjectCategoryMapper">
  <select id="selectList" resultType="com.example.demo.entity.CmsSubjectCategory">
    SELECT * FROM cms_subject_category
    <where>
      <!-- 动态条件由QueryWrapper生成 -->
    </where>
  </select>
</mapper>