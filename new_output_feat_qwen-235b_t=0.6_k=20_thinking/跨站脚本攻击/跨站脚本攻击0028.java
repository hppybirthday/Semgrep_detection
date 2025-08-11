package com.example.app.controller;

import com.example.app.service.CategoryService;
import com.example.app.util.HtmlRenderer;
import com.example.app.model.Category;
import com.example.app.util.EscapeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

/**
 * 分类管理控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/category")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    /**
     * 分类层级展示
     * @param parentId 父分类ID
     * @param backParentId 返回父级标识
     * @param categoryLevel 当前分类层级
     * @return HTML渲染结果
     */
    @RequestMapping("/hierarchy")
    @ResponseBody
    public String showHierarchy(@RequestParam("parentId") String parentId,
                               @RequestParam("backParentId") String backParentId,
                               @RequestParam("categoryLevel") String categoryLevel) {
        
        // 模拟业务逻辑处理
        Category processedCategory = processCategory(parentId, backParentId, categoryLevel);
        
        // 生成HTML响应
        return HtmlRenderer.buildCategoryPage(processedCategory);
    }

    private Category processCategory(String parentId, String backParentId, String categoryLevel) {
        // 复杂业务逻辑处理链
        Category category = new Category();
        category.setId(Integer.parseInt(parentId));
        category.setName("分类_" + parentId);
        
        // 调用服务层进行数据增强
        categoryService.enhanceCategory(category, backParentId, categoryLevel);
        
        // 潜在危险的数据传递
        category.setDescription("层级路径: " + categoryLevel + " > " + backParentId);
        
        return category;
    }
}

// -------------------------------
// 服务层代码
// -------------------------------
package com.example.app.service;

import com.example.app.model.Category;
import org.springframework.stereotype.Service;

@Service
public class CategoryService {
    public void enhanceCategory(Category category, String backParentId, String categoryLevel) {
        // 模拟多级数据处理
        String enrichedName = enrichName(category.getName(), backParentId);
        category.setName(enrichedName);
        
        // 潜在漏洞点：将未经处理的用户输入存储到对象中
        category.setMetaInfo("<script>maliciousCode('" + backParentId + "')</script>");
    }

    private String enrichName(String baseName, String backParentId) {
        // 看似安全的处理但实际未净化
        return baseName + "_v2_" + backParentId.hashCode();
    }
}

// -------------------------------
// HTML渲染工具类
// -------------------------------
package com.example.app.util;

import com.example.app.model.Category;

public class HtmlRenderer {
    public static String buildCategoryPage(Category category) {
        StringBuilder html = new StringBuilder();
        
        html.append("<html><body>");
        html.append("<h1>分类详情 - ").append(category.getName()).append("</h1>");
        html.append("<div class='info'>");
        html.append("  <p>ID: ").append(category.getId()).append("</p>");
        html.append("  <p>描述: ").append(category.getDescription()).append("</p>");
        html.append("  <p>元信息: ").append(category.getMetaInfo()).append("</p>");
        html.append("</div>");
        
        // 漏洞触发点：直接插入未净化的脚本
        html.append("<script>initializeCategory({");
        html.append("  id: ").append(category.getId()).append(",");
        html.append("  name: '").append(category.getName()).append("',");
        html.append("  level: '").append(category.getLevel()).append("'");
        html.append("});</script>");
        
        html.append("</body></html>");
        return html.toString();
    }
}

// -------------------------------
// 模型类
// -------------------------------
package com.example.app.model;

public class Category {
    private int id;
    private String name;
    private String description;
    private String metaInfo;
    private String level;

    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getMetaInfo() { return metaInfo; }
    public void setMetaInfo(String metaInfo) { this.metaInfo = metaInfo; }
    
    public String getLevel() { return level; }
    public void setLevel(String level) { this.level = level; }
}

// -------------------------------
// 伪装的安全工具类（存在误导性代码）
// -------------------------------
package com.example.app.util;

public class EscapeUtil {
    // 看似安全的转义方法但未被正确调用
    public static String safeEscape(String input) {
        if (input == null) return null;
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
    
    // 被错误使用的防御方法
    public static String removeScript(String input) {
        return input.replaceAll("(?i)<script.*?>.*?</script>", "");
    }
}