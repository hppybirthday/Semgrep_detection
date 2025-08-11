package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class DeviceController {
    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    @GetMapping("/list")
    public List<Device> getDevices(@RequestParam(required = false) String username,
                                   @RequestParam(required = false) String mobile,
                                   @RequestParam(defaultValue = "id") String sort,
                                   @RequestParam(defaultValue = "asc") String order) {
        return deviceService.findDevices(username, mobile, sort, order);
    }

    @GetMapping("/detail/{id}")
    public Device getDeviceById(@PathVariable String id) {
        return deviceService.getDeviceById(id);
    }

    public static void main(String[] args) {
        SpringApplication.run(DeviceController.class, args);
    }
}

class Device {
    private Long id;
    private String username;
    private String mobile;
    private String deviceType;
    // getters and setters
}

interface DeviceService {
    List<Device> findDevices(String username, String mobile, String sort, String order);
    Device getDeviceById(String id);
}

// MyBatis Mapper
@Mapper
interface DeviceMapper {
    @Select({"<script>",
      "SELECT * FROM devices WHERE 1=1",
      "<if test='username != null'> AND username LIKE CONCAT('%', #{username}, '%') </if>",
      "<if test='mobile != null'> AND mobile = #{mobile} </if>",
      "ORDER BY ${sort} ${order}",
      "</script>"})
    List<Device> searchDevices(@Param("username") String username,
                              @Param("mobile") String mobile,
                              @Param("sort") String sort,
                              @Param("order") String order);

    @Select("SELECT * FROM devices WHERE id = #{id}")
    Device selectById(String id);
}

// Simulated service implementation
class DeviceServiceImpl implements DeviceService {
    private final DeviceMapper deviceMapper;

    public DeviceServiceImpl(DeviceMapper deviceMapper) {
        this.deviceMapper = deviceMapper;
    }

    @Override
    public List<Device> findDevices(String username, String mobile, String sort, String order) {
        return deviceMapper.searchDevices(username, mobile, sort, order);
    }

    @Override
    public Device getDeviceById(String id) {
        return deviceMapper.selectById(id);
    }
}