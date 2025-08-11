package com.example.bigdata.controller;

import com.example.bigdata.service.CategoryService;
import com.example.bigdata.common.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 分类数据管理Controller
 * 攻击面：/category/secondary/getTableData?sSearch= 参数
 *        /save/category?id= 参数
 */
@RestController
@RequestMapping("/category")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    /**
     * 搜索分类数据接口
     * @param sSearch 搜索关键词
     * @param pageNum 页码
     * @param pageSize 页大小
     * @return 分页数据
     */
    @GetMapping("/secondary/getTableData")
    public Response getTableData(@RequestParam String sSearch,
                               @RequestParam int pageNum,
                               @RequestParam int pageSize) {
        return Response.success(categoryService.searchCategories(sSearch, pageNum, pageSize));
    }

    /**
     * 保存分类排序接口
     * @param id 分类ID
     * @param order 排序字段
     * @return 操作结果
     */
    @PutMapping("/save/category")
    public Response updateOrder(@RequestParam Long id,
                              @RequestParam String order) {
        categoryService.updateCategoryOrder(id, order);
        return Response.success();
    }
}

package com.example.bigdata.service;

import com.example.bigdata.mapper.CategoryMapper;
import com.example.bigdata.model.Category;
import com.example.bigdata.common.PageResult;
import com.example.bigdata.common.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 分类业务逻辑处理
 * 漏洞特征：将未经验证的参数直接传递给MyBatis动态SQL
 */
@Service
public class CategoryService {
    @Autowired
    private CategoryMapper categoryMapper;

    /**
     * 搜索分类数据
     * 问题：sSearch参数直接拼接到LIKE子句中
     */
    public PageResult<Category> searchCategories(String sSearch, int pageNum, int pageSize) {
        // 模拟分页处理
        int offset = (pageNum - 1) * pageSize;
        List<Category> categories = categoryMapper.searchCategories(sSearch, offset, pageSize);
        int total = categoryMapper.countCategories(sSearch);
        return new PageResult<>(categories, total);
    }

    /**
     * 更新分类排序
     * 问题：order参数直接拼接到ORDER BY子句
     */
    public void updateCategoryOrder(Long id, String order) {
        if (order == null || order.trim().isEmpty()) {
            order = "sort_order"; // 默认排序字段
        }
        categoryMapper.updateCategoryOrder(id, order);
    }
}

package com.example.bigdata.mapper;

import com.example.bigdata.model.Category;
import org.apache.ibatis.annotations.Param;
import java.util.List;

/**
 * 数据访问层接口
 * 漏洞位置：动态SQL使用${}导致注入
 */
public interface CategoryMapper {
    /**
     * 搜索分类数据（存在SQL注入漏洞）
     * 漏洞点：sSearch参数使用${}拼接
     */
    List<Category> searchCategories(@Param("sSearch") String sSearch,
                                    @Param("offset") int offset,
                                    @Param("pageSize") int pageSize);

    /**
     * 统计分类数量
     */
    int countCategories(@Param("sSearch") String sSearch);

    /**
     * 更新分类排序（存在SQL注入漏洞）
     * 漏洞点：order参数使用${}拼接
     */
    void updateCategoryOrder(@Param("id") Long id, @Param("order") String order);
}

/*
MyBatis XML映射文件：CategoryMapper.xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.bigdata.mapper.CategoryMapper">

  <!-- 存在SQL注入的查询 -->
  <select id="searchCategories" resultType="Category">
    SELECT * FROM categories
    WHERE name LIKE '%${sSearch}%'
    ORDER BY id
    LIMIT ${offset}, ${pageSize}
  </select>

  <!-- 存在SQL注入的更新 -->
  <update id="updateCategoryOrder">
    UPDATE categories
    SET sort_order = 1
    WHERE id = #{id}
    ORDER BY ${order}
  </update>

  <!-- 统计查询 -->
  <select id="countCategories" resultType="int">
    SELECT COUNT(*) FROM categories
    WHERE name LIKE '%${sSearch}%'
  </select>

</mapper>
*/