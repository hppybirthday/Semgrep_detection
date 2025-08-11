package com.chat.app.controller;

import com.chat.app.service.ChatCategoryService;
import com.chat.app.dto.CategoryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天分类管理Controller
 * 提供分类数据查询和保存功能
 */
@RestController
@RequestMapping("/category/secondary")
public class ChatCategoryController {
    @Autowired
    private ChatCategoryService categoryService;

    /**
     * 分页查询分类数据接口
     * 攻击面：sSearch参数存在SQL注入漏洞
     */
    @GetMapping("/getTableData")
    public List<CategoryDTO> getTableData(@RequestParam String sSearch, 
                                         @RequestParam int iDisplayStart,
                                         @RequestParam int iDisplayLength) {
        return categoryService.searchCategories(sSearch, iDisplayStart, iDisplayLength);
    }

    /**
     * 保存分类信息接口
     * 攻击面：id和name参数组合存在SQL注入漏洞
     */
    @PostMapping("/save/category")
    public boolean saveCategory(@RequestParam Long id, @RequestParam String name) {
        return categoryService.updateCategory(id, name);
    }
}

package com.chat.app.service;

import com.chat.app.mapper.CategoryMapper;
import com.chat.app.dto.CategoryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class ChatCategoryService {
    @Autowired
    private CategoryMapper categoryMapper;

    // 看似安全的输入验证（存在绕过漏洞）
    private boolean isValidInput(String input) {
        return input != null && Pattern.matches("^[a-zA-Z0-9_\\-\\s@.#]*$", input);
    }

    public List<CategoryDTO> searchCategories(String sSearch, int offset, int limit) {
        if (!isValidInput(sSearch)) return List.of();
        // 漏洞点：直接拼接搜索参数到SQL语句
        String searchCondition = "name LIKE '%" + sSearch + "%' OR description LIKE '%" + sSearch + "%'";
        return categoryMapper.search(searchCondition, offset, limit);
    }

    public boolean updateCategory(Long id, String name) {
        if (!isValidInput(name)) return false;
        // 漏洞点：将id和name直接拼接到动态SQL中
        String updateClause = "id = " + id + " SET name = '" + name + "'";
        return categoryMapper.updateDynamic(updateClause) > 0;
    }
}

package com.chat.app.mapper;

import com.chat.app.dto.CategoryDTO;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface CategoryMapper {
    /**
     * MyBatis XML映射文件对应的SQL存在注入漏洞
     * 使用${}而非#{}进行参数拼接
     */
    List<CategoryDTO> search(@Param("condition") String condition, 
                            @Param("offset") int offset,
                            @Param("limit") int limit);

    int updateDynamic(@Param("clause") String clause);
}

// MyBatis XML映射文件（CategoryMapper.xml）
<mapper namespace="com.chat.app.mapper.CategoryMapper">
    <select id="search" resultType="com.chat.app.dto.CategoryDTO">
        SELECT * FROM chat_categories
        <where>
            ${condition}
        </where>
        ORDER BY create_time DESC
        LIMIT ${offset}, ${limit}
    </select>

    <update id="updateDynamic">
        UPDATE chat_categories
        SET ${clause}
    </update>
</mapper>