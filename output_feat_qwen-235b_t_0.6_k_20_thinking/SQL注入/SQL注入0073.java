package com.example.demo.security;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

// Controller层（漏洞触发点）
@RestController
@RequestMapping("/category/secondary")
class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/getTableData")
    public PageInfo<Category> getTableData(@RequestParam String sSearch, 
                                           @RequestParam int pageNum, 
                                           @RequestParam int pageSize) {
        return categoryService.getTableData(sSearch, pageNum, pageSize);
    }

    @PostMapping("/save/category")
    public void saveCategory(@RequestParam String id, @RequestParam String name) {
        categoryService.saveCategory(id, name);
    }
}

// Service层（数据污染传递）
@Service
class CategoryService extends ServiceImpl<CategoryMapper, Category> {
    @Autowired
    private CategoryMapper categoryMapper;

    public PageInfo<Category> getTableData(String sSearch, int pageNum, int pageSize) {
        Page<Category> page = new Page<>(pageNum, pageSize);
        // 漏洞点：直接拼接用户输入到查询条件
        QueryWrapper<Category> wrapper = new QueryWrapper<>();
        wrapper.apply("name like '%{0}%'", sSearch); // 错误使用apply方法
        
        // 更隐蔽的漏洞形态
        List<Category> records = categoryMapper.selectByCondition(sSearch, page);
        page.setRecords(records);
        return new PageInfo<>(page);
    }

    public void saveCategory(String id, String name) {
        categoryMapper.updateById(id, name);
    }
}

// Mapper接口（SQL构造上下文）
interface CategoryMapper extends BaseMapper<Category> {
    List<Category> selectByCondition(@Param("sSearch") String sSearch, Page<Category> page);
    void updateById(@Param("id") String id, @Param("name") String name);
}

// 漏洞SQL构造（MyBatis XML配置）
// <mapper namespace="com.example.demo.security.CategoryMapper">
//     <select id="selectByCondition" resultType="com.example.demo.security.Category">
//         SELECT * FROM categories
//         <where>
//             name like '%${sSearch}%' <!-- 关键漏洞点 -->
//         </where>
//     </select>
//     <update id="updateById">
//         UPDATE categories SET name = '${name}' WHERE id = '${id}' <!-- 双参数漏洞 -->
//     </update>
// </mapper>

// 实体类
class Category {
    private String id;
    private String name;
    // 省略getter/setter
}

// 分页工具类（简化版）
class PageInfo<T> {
    public PageInfo(Page<T> page) {
        // 分页逻辑实现
    }
}