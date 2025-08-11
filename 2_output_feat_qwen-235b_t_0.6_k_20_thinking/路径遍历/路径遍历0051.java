package com.crm.core.plugin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class PluginManagerController {
    @Autowired
    private PluginService pluginService;

    // 加载插件配置
    @PostMapping("/plugin/load")
    public void loadPlugin(@RequestParam String pinyin, @RequestParam String content) throws IOException {
        // 调用插件服务保存配置
        pluginService.savePlugin(pinyin, content);
    }
}

class PluginService {
    // 保存插件文件
    public void savePlugin(String pinyin, String content) throws IOException {
        // 构造存储路径（业务逻辑：拼音作为插件标识）
        String pluginPath = "/opt/crm/plugins/" + pinyin + "/config.txt";
        
        // 调用文件工具写入
        FileUtil.writeToFile(pluginPath, content);
    }
}

class FileUtil {
    // 写入文件内容（模拟插件配置持久化）
    public static void writeToFile(String path, String content) throws IOException {
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(content);
        }
    }
}