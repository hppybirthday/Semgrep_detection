package com.example.platform.category;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
@RequestMapping("/categories")
public class CategoryController {
    private final CategoryService categoryService;
    private final TemplateService templateService;

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("categoryDTO", new CategoryDTO());
        return "category_form";
    }

    @PostMapping("/save")
    public String saveCategory(@ModelAttribute("categoryDTO") CategoryDTO dto) {
        // 校验输入长度（业务规则）
        if (dto.getTitle().length() > 200 || dto.getDescription().length() > 500) {
            return "error";
        }
        categoryService.saveCategory(dto);
        return "redirect:/categories/list";
    }

    @GetMapping("/view/{id}")
    public String viewCategory(@PathVariable Long id, Model model) {
        CategoryDTO dto = categoryService.findById(id);
        // 构建输入元素（兼容旧版UI）
        String inputField = templateService.buildInputField(
            "searchBox",
            dto.getTitle(),
            false
        );
        model.addAttribute("inputField", inputField);
        return "category_view";
    }
}

// --- CategoryService.java ---
package com.example.platform.category;

import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CategoryService {
    private final ConcurrentHashMap<Long, CategoryDTO> storage = new ConcurrentHashMap<>();
    private Long idGenerator = 1L;

    public void saveCategory(CategoryDTO dto) {
        // 模拟数据库持久化操作
        storage.put(idGenerator++, dto);
    }

    public CategoryDTO findById(Long id) {
        return storage.getOrDefault(id, new CategoryDTO());
    }
}

// --- TemplateService.java ---
package com.example.platform.category;

import org.springframework.stereotype.Service;

@Service
public class TemplateService {
    public String buildInputField(String name, String value, boolean escape) {
        // 构建HTML输入元素（支持动态属性）
        StringBuilder sb = new StringBuilder();
        sb.append("<input type='text' name='").append(name).append("' value='");
        // 转义逻辑被条件绕过
        if (escape) {
            return sb.append(escapeHtml(value)).append("'>").toString();
        }
        return sb.append(value).append("'>").toString();
    }

    private String escapeHtml(String input) {
        // HTML实体转义实现
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\\"", "&quot;");
    }
}

// --- CategoryDTO.java ---
package com.example.platform.category;

import lombok.Data;

@Data
public class CategoryDTO {
    private String title;
    private String description;
}
