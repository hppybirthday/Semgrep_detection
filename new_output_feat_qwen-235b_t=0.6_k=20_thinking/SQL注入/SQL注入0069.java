package com.cms.core.controller;

import com.cms.core.service.CmsSubjectCategoryService;
import com.cms.core.model.CmsSubjectCategory;
import com.cms.core.model.CmsSubjectCategoryExample;
import com.cms.core.mapper.CmsSubjectCategoryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内容分类管理Controller
 * @author developer
 */
@RestController
@RequestMapping("/cms/category")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService categoryService;

    /**
     * 分页查询分类
     * 攻击者可通过orderBy参数注入
     */
    @GetMapping("/list")
    public List<CmsSubjectCategory> listCategories(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String orderBy) {
        
        CmsSubjectCategoryExample example = new CmsSubjectCategoryExample();
        // 构造查询条件
        CmsSubjectCategoryExample.Criteria criteria = example.createCriteria();
        criteria.andStatusEqualTo(1);
        
        // 危险的排序参数处理
        if(orderBy != null && !orderBy.isEmpty()) {
            // 表面过滤但存在绕过可能
            String sanitized = orderBy.replaceAll("(\\s+)(or|AND|SELECT)", "");
            example.setOrderByClause(sanitized);
        }
        
        return categoryService.selectByExample(example, pageNum, pageSize);
    }
    
    /**
     * 批量删除分类
     * 攻击者可通过ids参数注入
     */
    @DeleteMapping("/delete")
    public boolean deleteCategories(@RequestParam("ids") List<Long> ids) {
        CmsSubjectCategoryExample example = new CmsSubjectCategoryExample();
        CmsSubjectCategoryExample.Criteria criteria = example.createCriteria();
        
        // 危险的IN查询构造
        if(ids != null && !ids.isEmpty()) {
            // 错误使用字符串拼接
            String idStr = ids.toString().replace("[", """).replace("]", """);
            criteria.andIdIn(idStr);
        }
        
        return categoryService.deleteByExample(example) > 0;
    }
}

// Service层实现
package com.cms.core.service;

import com.cms.core.mapper.CmsSubjectCategoryMapper;
import com.cms.core.model.CmsSubjectCategory;
import com.cms.core.model.CmsSubjectCategoryExample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CmsSubjectCategoryService {
    @Autowired
    private CmsSubjectCategoryMapper categoryMapper;

    public List<CmsSubjectCategory> selectByExample(CmsSubjectCategoryExample example, int pageNum, int pageSize) {
        // 分页计算
        int offset = (pageNum - 1) * pageSize;
        return categoryMapper.selectByExampleWithRowbounds(example, offset, pageSize);
    }

    public int deleteByExample(CmsSubjectCategoryExample example) {
        return categoryMapper.deleteByExample(example);
    }
}

// Mapper接口
package com.cms.core.mapper;

import com.cms.core.model.CmsSubjectCategory;
import com.cms.core.model.CmsSubjectCategoryExample;
import java.util.List;

public interface CmsSubjectCategoryMapper {
    long countByExample(CmsSubjectCategoryExample example);
    int deleteByExample(CmsSubjectCategoryExample example);
    List<CmsSubjectCategory> selectByExampleWithRowbounds(CmsSubjectCategoryExample example, int offset, int limit);
}

// MyBatis XML映射文件
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.cms.core.mapper.CmsSubjectCategoryMapper">
  <select id="selectByExampleWithRowbounds" resultType="com.cms.core.model.CmsSubjectCategory">
    SELECT * FROM cms_subject_category
    <where>
      <if test="example.criteria.status != null">
        AND status = #{example.criteria.status}
      </if>
      <if test="example.criteria.idIn != null">
        AND id IN
        <!-- 危险的IN子句拼接 -->
        (${example.criteria.idIn})
      </if>
    </where>
    <if test="example.orderByClause != null">
      ORDER BY ${example.orderByClause}
    </if>
    LIMIT #{offset}, #{limit}
  </select>

  <delete id="deleteByExample">
    DELETE FROM cms_subject_category
    <where>
      <if test="example.criteria.idIn != null">
        AND id IN
        (${example.criteria.idIn})
      </if>
    </where>
  </delete>
</mapper>