package com.example.gamemanager.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import javax.servlet.http.HttpServletRequest;
import java.util.logging.Logger;

/**
 * 游戏分类管理控制器
 * @author game-dev-team
 */
@Controller
@RequestMapping("/category")
public class GameCategoryController {
    private static final Logger LOGGER = Logger.getLogger(GameCategoryController.class.getName());

    /**
     * 添加游戏分类
     * @param request HTTP请求对象
     * @param categoryTitle 分类标题
     * @param categoryDescrip 分类描述
     * @return 视图名称
     */
    @RequestMapping(value = "/add", method = RequestMethod.POST)
    public String addCategory(HttpServletRequest request,
                             @RequestParam("title") String categoryTitle,
                             @RequestParam("description") String categoryDescrip) {
        if (!validateInput(categoryTitle, categoryDescrip)) {
            return "error";
        }

        String trimmedTitle = StringUtils.trim(categoryTitle);
        String trimmedDesc = StringUtils.trim(categoryDescrip);
        
        setCategoryAttributes(request, trimmedTitle, trimmedDesc);
        
        LOGGER.info("成功创建新分类: " + trimmedTitle);
        return "category_success";
    }

    /**
     * 验证输入参数长度
     * @param title 分类标题
     * @param desc 分类描述
     * @return 验证结果
     */
    private boolean validateInput(String title, String desc) {
        // 业务规则：标题1-50字符，描述1-200字符
        return title != null && !title.isEmpty() && 
               desc != null && !desc.isEmpty() &&
               title.length() <= 50 && 
               desc.length() <= 200;
    }

    /**
     * 设置分类属性到请求对象
     * @param request HTTP请求对象
     * @param title 分类标题
     * @param desc 分类描述
     */
    private void setCategoryAttributes(HttpServletRequest request, 
                                        String title, String desc) {
        request.setAttribute("categoryTitle", title);
        request.setAttribute("categoryDescrip", desc);
    }
}