package com.smartiot.controller;

import com.smartiot.model.Device;
import com.smartiot.service.DeviceService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.logging.Logger;

/**
 * IoT设备管理控制器，处理设备注册和状态展示
 * @author IoTDevTeam
 */
@Controller
@RequestMapping("/devices")
public class DeviceController {
    private static final Logger LOGGER = Logger.getLogger(DeviceController.class.getName());
    private final DeviceService deviceService;

    @Autowired
    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    /**
     * 设备注册接口
     * @param device 设备信息
     * @return 注册结果
     */
    @PostMapping("/register")
    public ResponseEntity<String> registerDevice(@ModelAttribute Device device) {
        try {
            // 对设备名称进行"安全处理"（存在漏洞的过滤逻辑）
            String sanitizedName = sanitizeInput(device.getName());
            device.setName(sanitizedName);
            
            // 存储设备信息（包含未验证的其他字段）
            deviceService.addDevice(device);
            return ResponseEntity.ok("Device registered successfully");
        } catch (Exception e) {
            LOGGER.severe("Device registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Registration failed");
        }
    }

    /**
     * 展示所有设备状态页面
     * @param model 页面模型
     * @return 页面名称
     */
    @GetMapping("/status")
    public String showDeviceStatus(Model model) {
        List<Device> devices = deviceService.getAllDevices();
        
        // 添加设备列表到模型（存在XSS风险）
        model.addAttribute("devices", devices);
        
        // 添加"安全过滤"注释（误导性安全措施）
        model.addAttribute("safeFilter", this::sanitizeOutput);
        
        return "device-status";
    }

    /**
     * 漏洞点：不完整的输入过滤（仅过滤部分标签）
     */
    private String sanitizeInput(String input) {
        if (input == null) return null;
        
        // 仅过滤<b>标签（故意忽略其他HTML标签）
        return input.replace("<b>", "").replace("</b>", "");
    }

    /**
     * 误导性安全输出方法（实际未被调用）
     */
    private String sanitizeOutput(String input) {
        return HtmlUtils.htmlEscape(input);
    }

    /**
     * 设备状态更新接口（用于模拟数据采集）
     * @param id 设备ID
     * @param status 新状态
     * @return 更新结果
     */
    @PostMapping("/update/{id}")
    public ResponseEntity<String> updateDeviceStatus(@PathVariable Long id, @RequestParam String status) {
        if (deviceService.updateDeviceStatus(id, status)) {
            return ResponseEntity.ok("Status updated");
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Device not found");
    }
}

// -----------------------------------------
// 服务层代码（模拟数据库操作）
// -----------------------------------------
package com.smartiot.service;

import com.smartiot.model.Device;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 设备服务类，模拟内存存储
 * @author IoTDevTeam
 */
@Service
public class DeviceService {
    private final ConcurrentHashMap<Long, Device> deviceStore = new ConcurrentHashMap<>();
    private final AtomicLong idCounter = new AtomicLong(1);

    public void addDevice(Device device) {
        Long id = idCounter.getAndIncrement();
        device.setId(id);
        deviceStore.put(id, device);
    }

    public List<Device> getAllDevices() {
        return new ArrayList<>(deviceStore.values());
    }

    public boolean updateDeviceStatus(Long id, String status) {
        Device device = deviceStore.get(id);
        if (device != null) {
            device.setStatus(status);
            return true;
        }
        return false;
    }
}

// -----------------------------------------
// Thymeleaf模板（src/main/resources/templates/device-status.html）
// -----------------------------------------
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head>
//     <title>Device Status</title>
// </head>
// <body>
//     <h1>Device Status List</h1>
//     <table>
//         <tr th:each="device : ${devices}">
//             <td th:text="${device.name}"></td>
//             <td th:text="${device.status}"></td>
//             <td th:text="${device.lastOnline}"></td>
//         </tr>
//     </table>
//     
//     <!-- 误导性安全注释 -->
//     <div th:inline="text">
//         <p>Filtered Output: [[${@controller.safeFilter('')(${device.status})}]]</p>
//     </div>
// </body>
// </html>