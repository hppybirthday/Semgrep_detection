package com.example.vulnerable.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.Map;

/**
 * 云原生微服务架构中的Redis反序列化漏洞示例
 * 模拟内容管理系统(CMS)的Token存储服务
 */
@Service
public class RedisTemplateTokenStore {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 从Redis读取并反序列化文章对象
     * 漏洞点：使用不安全的反序列化方式处理外部输入
     */
    public Post readValue(String key) {
        // 模拟从Redis获取原始数据
        byte[] rawData = (byte[]) redisTemplate.opsForValue().get(key);
        if (rawData == null) return null;

        try {
            // 调用不安全的反序列化方法链
            return readValueFromRedis(rawData);
        } catch (Exception e) {
            // 异常处理掩盖了安全问题
            logError("反序列化失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 漏洞核心：不安全的反序列化实现
     * 通过Fastjson的autoType特性实现任意类型反序列化
     */
    private Post readValueFromRedis(byte[] data) {
        // 使用默认ObjectMapper配置（未禁用enableDefaultTyping）
        ObjectMapper mapper = new ObjectMapper();
        // 漏洞触发点：从JSON字符串反序列化为对象
        return mapper.readValue(data, Post.class);
    }

    /**
     * 模拟业务日志记录
     */
    private void logError(String message) {
        // 实际环境中可能被监控系统忽略
        System.err.println("[安全警告] " + message);
    }

    /**
     * 漏洞利用载体：文章实体类
     * 包含可能导致RCE的危险注解
     */
    public static class Post {
        // 正常业务字段
        private String title;
        private String content;
        
        // 危险注解字段：LAST_ASSOCIATED_CATEGORIES_ANNO
        // 攻击者可通过该字段注入恶意模板
        @SuppressWarnings("unused")
        private Map<String, Object> metadata;

        // Fastjson反序列化时自动调用的初始化方法
        public void init() {
            // 正常情况下初始化分类信息
            // 攻击情况下可能触发恶意代码执行
            if (metadata != null && metadata.containsKey("template")) {
                Object template = metadata.get("template");
                // 模拟模板渲染操作
                if (template instanceof String) {
                    // 实际执行上下文可能包含危险操作
                    System.out.println("渲染模板: " + template);
                }
            }
        }
    }
}

// 漏洞利用示例（攻击者构造的恶意JSON）:
// {
//   "@type": "com.example.vulnerable.service.RedisTemplateTokenStore$Post",
//   "metadata": {
//     "template": {
//       "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
//       "_bytecodes": ["恶意字节码base64"],
//       "_name": "a",
//       "_tfactory": {}
//     }
//   }
// }
