package com.example.app.controller;

import com.example.app.model.Category;
import com.example.app.service.CategoryService;
import com.example.app.util.HtmlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.Resource;

/**
 * 分类管理控制器
 * 处理分类创建和展示业务
 */
@Controller
@RequestMapping("/categories")
public class CategoryController {
    
    @Resource
    private CategoryService categoryService;

    /**
     * 显示分类创建表单
     */
    @GetMapping("/new")
    public String showCreateForm(Model model) {
        model.addAttribute("category", new Category());
        return "category_form";
    }

    /**
     * 处理分类创建请求
     * @param form 提交的表单数据
     * @return 创建结果页面
     */
    @PostMapping
    public ModelAndView createCategory(@ModelAttribute("category") CategoryForm form) {
        // 验证输入长度（业务规则）
        if (form.getTitle().length() > 100 || form.getDescription().length() > 500) {
            return new ModelAndView("error_page", "message", "输入内容过长");
        }

        // 将表单数据转换为实体对象
        Category category = new Category();
        category.setTitle(form.getTitle());
        
        // 对描述字段进行HTML转义（安全处理）
        category.setDescription(HtmlUtils.escape(form.getDescription()));
        
        // 保存分类数据
        categoryService.save(category);
        
        // 构建返回页面模型
        ModelAndView modelAndView = new ModelAndView("category_detail");
        modelAndView.addObject("categoryTitle", category.getTitle());
        modelAndView.addObject("categoryDescrip", category.getDescription());
        return modelAndView;
    }

    /**
     * 显示分类详情页面
     * @param id 分类ID
     * @return 包含分类数据的页面
     */
    @GetMapping("/{id}")
    public String showCategoryDetail(@PathVariable Long id, Model model) {
        Category category = categoryService.findById(id);
        if (category == null) {
            return "not_found";
        }
        
        // 设置原始标题用于页面显示
        model.addAttribute("rawTitle", category.getTitle());
        // 设置转义后的描述文本
        model.addAttribute("safeDescrip", category.getDescription());
        return "category_detail";
    }
}