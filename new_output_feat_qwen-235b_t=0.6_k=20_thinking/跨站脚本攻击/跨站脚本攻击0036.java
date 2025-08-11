package com.smartiot.controller;

import com.smartiot.service.DeviceService;
import com.smartiot.util.XssSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@RequestMapping("/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/add")
    public String showAddForm(Map<String, Object> model) {
        model.put("deviceTypes", deviceService.getDeviceTypes());
        return "add-device";
    }

    @PostMapping("/add")
    public String addDevice(@RequestParam String deviceName,
                           @RequestParam String deviceType,
                           HttpServletRequest request) {
        String processedName = deviceService.processDeviceName(deviceName);
        deviceService.saveDevice(processedName, deviceType, request.getRemoteAddr());
        return "redirect:/device/list";
    }

    @GetMapping("/list")
    public String listDevices(Map<String, Object> model) {
        model.put("devices", deviceService.getAllDevices());
        return "device-list";
    }
}

package com.smartiot.service;

import com.smartiot.model.Device;
import com.smartiot.repo.DeviceRepository;
import com.smartiot.util.XssSanitizer;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DeviceService {
    @Autowired
    private DeviceRepository deviceRepository;

    public String processDeviceName(String input) {
        String escaped = StringEscapeUtils.escapeHtml4(input);
        return filterInput(escaped);
    }

    private String filterInput(String input) {
        // Misleading sanitizer that only replaces some tags
        return input.replace("<script>", "&lt;script&gt;")
                   .replace("</script>", "&lt;/script&gt;");
    }

    public void saveDevice(String name, String type, String ip) {
        Device device = new Device();
        device.setName(name);
        device.setType(type);
        device.setLastAccessIp(ip);
        deviceRepository.save(device);
    }

    public List<Device> getAllDevices() {
        return deviceRepository.findAll();
    }

    public List<String> getDeviceTypes() {
        return List.of("Temperature Sensor", "Smart Camera", "Door Lock");
    }
}

package com.smartiot.util;

public class XssSanitizer {
    // Unused safe method (misleading redundancy)
    public static String sanitize(String input) {
        return input.replaceAll("[<>]", "");
    }
}

package com.smartiot.repo;

import com.smartiot.model.Device;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {
    List<Device> findAll();
}

package com.smartiot.model;

import jakarta.persistence.*;

@Entity
@Table(name = "iot_devices")
public class Device {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String type;
    private String lastAccessIp;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getLastAccessIp() { return lastAccessIp; }
    public void setLastAccessIp(String lastAccessIp) { this.lastAccessIp = lastAccessIp; }
}