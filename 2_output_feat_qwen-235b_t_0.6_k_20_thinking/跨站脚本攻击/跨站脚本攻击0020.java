package com.crm.advert.controller;

import com.crm.advert.dto.AdvertDTO;
import com.crm.advert.service.AdvertService;
import com.crm.common.exception.ValidationException;
import com.crm.common.response.ApiResponse;
import com.crm.common.xss.XssCleanIgnore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 广告提交控制器
 * 处理广告内容创建与校验
 */
@Controller
public class AdvertController {
    @Autowired
    private AdvertService advertService;

    /**
     * 提交广告内容
     * 校验广告标题长度（最大50字符）
     */
    @PostMapping("/submit")
    @ResponseBody
    public ApiResponse submitAdvert(@XssCleanIgnore @RequestBody AdvertDTO dto) {
        try {
            if (dto.getTitle().length() > 50) {
                throw new ValidationException("标题过长", dto.getTitle());
            }
            advertService.saveAdvert(dto);
            return ApiResponse.success("提交成功");
        } catch (ValidationException e) {
            return ApiResponse.error(400, "校验失败: " + e.getMessage());
        }
    }
}

/**
 * XSS漏洞触发点：当校验失败时，错误信息直接拼接原始输入内容
 * 攻击者可通过构造恶意标题（如：<script>alert(document.cookie)</script>）
 * 在错误页面渲染时触发脚本执行
 */