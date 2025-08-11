package com.gamestudio.cms.controller;

import com.gamestudio.cms.service.CmsSubjectCategoryService;
import com.gamestudio.cms.model.CmsSubjectCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 桌面游戏主题分类管理Controller
 * Created by gamestudio on 2023/9/15.
 */
@RestController
@RequestMapping("/api/cms/subject/category")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService categoryService;

    /**
     * 根据名称模糊查询分类
     * 支持按游戏类型过滤
     */
    @GetMapping("/search")
    public List<CmsSubjectCategory> searchCategories(@RequestParam String categoryName, 
                                                    @RequestParam(required = false) String gameType) {
        return categoryService.findCategories(categoryName, gameType);
    }

    /**
     * 批量删除分类
     * 参数格式：[1,2,3]
     */
    @PostMapping("/delete")
    public boolean deleteCategories(@RequestBody List<Long> ids) {
        return categoryService.deleteCategories(ids);
    }
}

// Service层实现
package com.gamestudio.cms.service;

import com.gamestudio.cms.mapper.CmsSubjectCategoryMapper;
import com.gamestudio.cms.model.CmsSubjectCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CmsSubjectCategoryService {
    @Autowired
    private CmsSubjectCategoryMapper categoryMapper;

    public List<CmsSubjectCategory> findCategories(String categoryName, String gameType) {
        // 构造动态查询条件
        StringBuilder condition = new StringBuilder();
        condition.append("name like '%").append(categoryName).append("%' ");
        
        if (gameType != null && !gameType.isEmpty()) {
            condition.append("and type = '").append(gameType).append("'");
        }
        
        return categoryMapper.selectByCondition(condition.toString());
    }

    public boolean deleteCategories(List<Long> ids) {
        return categoryMapper.deleteBatch(ids) > 0;
    }
}

// Mapper接口
package com.gamestudio.cms.mapper;

import com.gamestudio.cms.model.CmsSubjectCategory;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;
import java.util.List;

public interface CmsSubjectCategoryMapper {
    @Select({"<script>",
      "SELECT * FROM cms_subject_category WHERE ${condition}",
      "</script>"})
    List<CmsSubjectCategory> selectByCondition(@Param("condition") String condition);

    @Delete({"<script>",
      "DELETE FROM cms_subject_category WHERE id IN",
      "<foreach collection='ids' item='id' open='(' separator=',' close=')'>",
        "#{id}",
      "</foreach>",
      "</script>"})
    int deleteBatch(List<Long> ids);
}