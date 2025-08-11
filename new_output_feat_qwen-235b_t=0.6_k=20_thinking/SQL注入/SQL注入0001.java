package com.cms.content.controller;

import com.cms.content.service.CategoryService;
import com.cms.content.model.CmsSubjectCategory;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 内容分类管理Controller
 * @author content-team
 */
@RestController
@Tag(name = "CategoryController", description = "内容分类管理")
@RequestMapping("/category/secondary")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @Operation(summary = "搜索分类")
    @GetMapping("/getTableData")
    @ResponseBody
    public Map<String, Object> getTableData(
            @Parameter(description = "搜索关键字") @RequestParam(required = false) String sSearch,
            @Parameter(description = "排序字段") @RequestParam String orderBy,
            @Parameter(description = "页码") @RequestParam int pageNum,
            @Parameter(description = "每页数量") @RequestParam int pageSize) {
        
        // 构造排序条件（存在漏洞）
        PageHelper.orderBy(orderBy);
        
        // 构造查询条件（存在漏洞）
        Map<String, Object> params = new HashMap<>();
        if (sSearch != null && !sSearch.isEmpty()) {
            // 错误地直接拼接LIKE条件
            params.put("searchCondition", "'%' + '" + sSearch + "' + '%'"");
        }
        
        List<CmsSubjectCategory> categories = categoryService.searchCategories(params, pageNum, pageSize);
        PageInfo<CmsSubjectCategory> pageInfo = new PageInfo<>(categories);
        
        Map<String, Object> result = new HashMap<>();
        result.put("data", pageInfo.getList());
        result.put("recordsTotal", pageInfo.getTotal());
        result.put("recordsFiltered", pageInfo.getTotal());
        return result;
    }

    @Operation(summary = "保存分类")
    @PostMapping("/save/category")
    @ResponseBody
    public Map<String, Object> saveCategory(
            @Parameter(description = "分类ID") @RequestParam Long id,
            @Parameter(description = "分类名称") @RequestParam String name) {
        
        // 构造更新参数（存在漏洞）
        Map<String, Object> params = new HashMap<>();
        params.put("id", id);
        // 错误地直接拼接字段值
        params.put("name", "'" + name + "'");
        
        boolean result = categoryService.updateCategory(params);
        Map<String, Object> response = new HashMap<>();
        response.put("success", result);
        return response;
    }
}

package com.cms.content.service;

import com.cms.content.mapper.CategoryMapper;
import com.cms.content.model.CmsSubjectCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 分类业务逻辑实现
 */
@Service
public class CategoryService {
    @Autowired
    private CategoryMapper categoryMapper;

    public List<CmsSubjectCategory> searchCategories(Map<String, Object> params, int pageNum, int pageSize) {
        // 存在漏洞的查询构造
        return categoryMapper.selectCategories(params, pageNum, pageSize);
    }

    public boolean updateCategory(Map<String, Object> params) {
        // 存在漏洞的更新操作
        return categoryMapper.updateCategory(params) > 0;
    }
}

package com.cms.content.mapper;

import com.cms.content.model.CmsSubjectCategory;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.SelectKey;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.One;
import org.apache.ibatis.annotations.Association;
import org.apache.ibatis.annotations.Collection;
import org.apache.ibatis.annotations.MapKey;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.UpdateProvider;
import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.DeleteProvider;
import org.apache.ibatis.builder.annotation.ProviderContext;
import org.apache.ibatis.jdbc.SQL;
import org.apache.ibatis.session.RowBounds;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.result.DefaultMapResultHandler;
import org.apache.ibatis.executor.result.ResultHandler;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.TransactionIsolationLevel;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.result.DefaultMapResultHandler;
import org.apache.ibatis.executor.result.ResultHandler;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.transaction.TransactionIsolationLevel;
import org.apache.ibatis.executor.BatchResult;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.result.DefaultMapResultHandler;
import org.apache.ibatis.executor.result.ResultHandler;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.mapping.StatementType;
import org.apache.ibatis.mapping.SqlCommandType;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.ExecutorType;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.transaction.Transaction;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.transaction.TransactionIsolationLevel;
import org.apache.ibatis.executor.BatchResult;
import java.util.List;
import java.util.Map;
import org.apache.ibatis.annotations.Mapper;

/**
 * 分类数据访问层
 */
@Mapper
public interface CategoryMapper {
    
    @Select({"<script>",
      "SELECT * FROM cms_subject_category WHERE 1=1",
      "<if test='params.searchCondition != null'>",
        "AND name LIKE CONCAT('%', " + "#{params.searchCondition}" + ")",
      "</if>",
      "</script>"})
    List<CmsSubjectCategory> selectCategories(@Param("params") Map<String, Object> params, @Param("pageNum") int pageNum, @Param("pageSize") int pageSize);

    // 存在漏洞的更新语句（直接拼接参数）
    @Update({"<script>",
      "UPDATE cms_subject_category SET name = " + "#{params.name}" + " WHERE id = " + "#{params.id}" + "",
      "</script>"})
    int updateCategory(@Param("params") Map<String, Object> params);
}

package com.cms.content.model;

import java.io.Serializable;
import java.util.Date;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

/**
 * cms_subject_category
 * @author 
 */
@Data
@ApiModel(value="CmsSubjectCategory对象", description="内容分类")
public class CmsSubjectCategory implements Serializable {
    private static final long serialVersionUID = 1L;

    @ApiModelProperty(value = "主键ID")
    private Long id;

    @ApiModelProperty(value = "分类名称")
    private String name;

    @ApiModelProperty(value = "排序")
    private Integer sort;

    @ApiModelProperty(value = "创建时间")
    private Date createTime;

    @ApiModelProperty(value = "更新时间")
    private Date updateTime;
}
