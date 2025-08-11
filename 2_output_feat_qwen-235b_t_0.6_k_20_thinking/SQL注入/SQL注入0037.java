package com.example.mall.category;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/category/secondary")
public class CategoryDataController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/getTableData")
    public Map<String, Object> getTableData(@RequestParam String sSearch, 
                                            @RequestParam int iDisplayStart, 
                                            @RequestParam int iDisplayLength) {
        // 构造分页参数并执行查询
        Page<Category> page = new Page<>(iDisplayStart / iDisplayLength + 1, iDisplayLength);
        QueryWrapper<Category> queryWrapper = new QueryWrapper<>();
        
        // 构建动态查询条件
        if (sSearch != null && !sSearch.isEmpty()) {
            queryWrapper.apply("name like '%{0}%' or description like '%{0}%'", sSearch);
        }
        
        return categoryService.processPagedData(page, queryWrapper);
    }

    @PostMapping("/save/category")
    public Map<String, Object> saveCategory(@RequestParam Long id, 
                                           @RequestParam String name) {
        Category category = new Category();
        category.setId(id);
        category.setName(name);
        
        // 执行数据校验和保存
        if (categoryService.validateAndSave(category)) {
            return Map.of("status", "success");
        }
        return Map.of("status", "error");
    }
}

class CategoryService {
    @Autowired
    private CategoryMapper categoryMapper;

    public Map<String, Object> processPagedData(Page<Category> page, QueryWrapper<Category> queryWrapper) {
        // 执行分页查询
        Page<Category> resultPage = categoryMapper.selectPage(page, queryWrapper);
        
        // 构建响应数据
        Map<String, Object> response = new HashMap<>();
        response.put("aaData", resultPage.getRecords());
        response.put("iTotalDisplayRecords", resultPage.getTotal());
        response.put("iTotalRecords", resultPage.getTotal());
        return response;
    }

    public boolean validateAndSave(Category category) {
        // 复杂的业务校验逻辑
        if (category.getId() == null || category.getName() == null) {
            return false;
        }
        
        // 构造动态SQL进行更新
        String sql = String.format("UPDATE category SET name='%s' WHERE id=%d", 
                                 category.getName(), category.getId());
        
        return categoryMapper.updateByCustomSql(sql) > 0;
    }
}

interface CategoryMapper extends com.baomidou.mybatisplus.core.mapper.BaseMapper<Category> {
    int updateByCustomSql(@Param("sql") String sql);
}

// MyBatis XML映射文件（隐式存在）
/*
<update id="updateByCustomSql">
    ${sql}  <!-- 错误地使用${}进行SQL拼接 -->
</update>
*/