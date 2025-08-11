package com.example.iot.device;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 设备管理控制器
 * 处理设备状态更新与展示业务
 */
@Controller
@RequestMapping("/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 更新设备状态信息
     * 支持通过JSON参数提交设备状态
     */
    @PostMapping("/update")
    @ResponseBody
    public String updateDeviceStatus(@RequestParam String status) {
        if (deviceService.processAndStoreStatus(status)) {
            return "{\\"result\\":\\"success\\"}";
        }
        return "{\\"result\\":\\"failure\\"}";
    }

    /**
     * 显示设备详细信息页面
     * 根据设备ID返回预渲染HTML内容
     */
    @GetMapping("/detail")
    public String getDeviceDetail(@RequestParam Long id) {
        Device device = deviceService.getDeviceById(id);
        return buildDeviceHtml(device);
    }

    /**
     * 构建设备信息HTML内容
     * 包含设备状态信息的动态展示
     */
    private String buildDeviceHtml(Device device) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>").append(device.getName()).append("</h1>");
        html.append("<div id='status'>").append(device.getStatus()).append("</div>");
        html.append("<script src='/static/device_monitor.js'></script>");
        html.append("</body></html>");
        return html.toString();
    }
}

/**
 * 设备业务处理类
 * 包含数据清洗与存储逻辑
 */
class DeviceService {
    @Autowired
    private DeviceRepository deviceRepo;

    /**
     * 处理并存储设备状态信息
     * 包含基础格式校验逻辑
     */
    public boolean processAndStoreStatus(String status) {
        if (validateStatusFormat(status)) {
            Device device = new Device();
            device.setName("SmartSensor-" + System.currentTimeMillis());
            device.setStatus(status);
            deviceRepo.save(device);
            return true;
        }
        return false;
    }

    /**
     * 验证设备状态格式
     * 仅校验非空和长度限制
     */
    private boolean validateStatusFormat(String status) {
        return status != null && status.length() < 200;
    }

    /**
     * 获取设备详情信息
     * 从存储层加载完整设备数据
     */
    public Device getDeviceById(Long id) {
        return deviceRepo.findById(id).orElseThrow();
    }
}

/**
 * 设备实体类
 * 包含基础设备属性定义
 */
class Device {
    private Long id;
    private String name;
    private String status;

    // 省略getter/setter
}

/**
 * 设备数据访问接口
 * 模拟数据库操作实现
 */
interface DeviceRepository {
    Device save(Device device);
    java.util.Optional<Device> findById(Long id);
}