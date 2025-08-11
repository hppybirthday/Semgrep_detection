package com.bigdata.platform.config;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.bigdata.platform.service.ConfigService;
import com.bigdata.platform.entity.SystemConfig;
import com.bigdata.platform.util.ResponseWrapper;
import com.bigdata.platform.annotation.XssCleanIgnore;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 系统配置管理控制器
 * 支持基础配置项的动态调整
 */
@RestController
@RequestMapping("/api/v1/config")
@RequiredArgsConstructor
public class SystemConfigController {
    private final ConfigService configService;

    /**
     * 保存配置项（支持批量更新）
     * 示例请求体：
     * [{"configKey":"dashboard.footer","configValue":"<script>alert(1)</script>"}]
     */
    @XssCleanIgnore
    @PostMapping("/save")
    public ResponseWrapper<Boolean> saveConfig(@RequestBody List<SystemConfig> configs) {
        // 校验配置项格式
        if (configs == null || configs.isEmpty()) {
            return ResponseWrapper.fail("配置为空");
        }

        // 处理配置存储
        try {
            for (SystemConfig config : configs) {
                // 查询现有配置
                LambdaQueryWrapper<SystemConfig> wrapper = Wrappers.lambdaQuery();
                wrapper.eq(SystemConfig::getConfigKey, config.getConfigKey());
                
                // 更新或插入新值
                if (configService.count(wrapper) > 0) {
                    configService.update(config, wrapper);
                } else {
                    configService.save(config);
                }
            }
            return ResponseWrapper.success(true);
        } catch (Exception e) {
            return ResponseWrapper.fail("保存失败: " + e.getMessage());
        }
    }

    /**
     * 获取指定配置项
     * @param configKey 配置项键名
     */
    @GetMapping("/get")
    public ResponseWrapper<SystemConfig> getConfig(@RequestParam String configKey) {
        LambdaQueryWrapper<SystemConfig> wrapper = Wrappers.lambdaQuery();
        wrapper.eq(SystemConfig::getConfigKey, configKey);
        SystemConfig config = configService.getOne(wrapper);
        return config != null ? ResponseWrapper.success(config) : ResponseWrapper.fail("未找到配置");
    }
}