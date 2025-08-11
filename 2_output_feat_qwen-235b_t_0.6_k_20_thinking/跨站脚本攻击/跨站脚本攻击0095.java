package com.smartiot.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DeviceStatusController {
    
    private final DeviceService deviceService;
    private final TemplateRenderer templateRenderer;

    public DeviceStatusController(DeviceService deviceService, TemplateRenderer templateRenderer) {
        this.deviceService = deviceService;
        this.templateRenderer = templateRenderer;
    }

    @GetMapping("/search")
    public String searchDevices(@RequestParam("keyword") String keyword, Model model) {
        // 处理搜索请求并验证输入长度（业务规则）
        if (keyword.length() > 100) {
            model.addAttribute("error", "搜索关键词过长");
            return "error";
        }

        // 获取设备列表并构建显示数据
        List<Device> devices = deviceService.findDevices(keyword);
        String displayContent = templateRenderer.buildDisplayContent(devices, keyword);
        
        model.addAttribute("content", displayContent);
        return "device_list";
    }
}

class TemplateRenderer {
    
    String buildDisplayContent(List<Device> devices, String keyword) {
        StringBuilder content = new StringBuilder();
        
        // 构建设备显示HTML（业务需求）
        for (Device device : devices) {
            content.append("<div class='device'>")
                   .append("<h3>").append(device.getName()).append("</h3>")
                   .append("<p>").append(device.getStatus()).append("</p>")
                   .append("</div>");
        }
        
        // 添加搜索统计信息（业务功能）
        content.append("<div class='stats'>")
               .append("搜索关键词: ").append(keyword)
               .append(" | 结果数量: ").append(devices.size())
               .append("</div>");
               
        return content.toString();
    }
}

record Device(String name, String status) {}