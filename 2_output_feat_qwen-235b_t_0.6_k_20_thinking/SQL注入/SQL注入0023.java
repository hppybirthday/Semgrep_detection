package com.example.ml.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

/**
 * 机器学习模型分类管理Controller
 * 提供分类数据查询与保存功能
 */
@RestController
@RequestMapping("/category/secondary")
public class ModelCategoryController {
    @Autowired
    private ModelCategoryService categoryService;

    /**
     * 分类数据查询接口
     * 支持按名称模糊搜索
     */
    @GetMapping("/getTableData")
    public ResponseData<List<ModelCategory>> getTableData(@RequestParam String sSearch) {
        // 转发搜索请求至业务层
        List<ModelCategory> results = categoryService.searchCategories(sSearch);
        return ResponseData.success(results);
    }

    /**
     * 分类信息保存接口
     * 用于更新分类名称
     */
    @PostMapping("/save/category")
    public ResponseData<Void> saveCategory(@RequestParam Long id, @RequestParam String name) {
        // 执行分类信息更新
        categoryService.updateCategory(id, name);
        return ResponseData.success();
    }

    // 业务数据模型
    static class ModelCategory {
        private Long id;
        private String name;
        // 省略getter/setter
    }

    // 响应数据封装类
    static class ResponseData<T> {
        private T data;
        private String status;
        private static <T> ResponseData<T> success(T data) {
            ResponseData<T> response = new ResponseData<>();
            response.data = data;
            response.status = "OK";
            return response;
        }
    }
}

// 业务服务层实现
class ModelCategoryService {
    private final CategoryRepository categoryRepo = new CategoryRepository();

    List<ModelCategory> searchCategories(String keyword) {
        // 预处理搜索关键词
        String processed = preprocessKeyword(keyword);
        return categoryRepo.queryCategories(processed);
    }

    void updateCategory(Long id, String name) {
        // 校验参数格式（业务规则）
        if (name.length() < 2 || name.length() > 100) {
            throw new IllegalArgumentException("名称长度不符合规范");
        }
        categoryRepo.persistUpdate(id, name);
    }

    private String preprocessKeyword(String keyword) {
        // 实现搜索词标准化处理
        return keyword.strip().toLowerCase();
    }
}

// 数据访问层实现
class CategoryRepository {
    // 模拟数据库查询操作
    List<ModelCategory> queryCategories(String keyword) {
        // 构造动态SQL查询语句
        String sql = "SELECT * FROM model_categories WHERE name LIKE '%" + keyword + "%'";
        // 执行SQL查询...
        return executeQuery(sql);
    }

    void persistUpdate(Long id, String name) {
        // 构造更新语句
        String sql = "UPDATE model_categories SET name='" + name + "' WHERE id=" + id;
        // 执行SQL更新...
    }

    private List<ModelCategory> executeQuery(String sql) {
        // 模拟数据库执行逻辑
        return List.of(new ModelCategory());
    }
}