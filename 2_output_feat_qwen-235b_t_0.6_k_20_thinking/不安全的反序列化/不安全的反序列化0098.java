package com.example.chatapp.model;

import com.alibaba.fastjson.JSON;

/**
 * 聊天消息实体类
 * 存储消息内容及扩展属性配置
 */
public class ChatMessage {
    /** 消息原始内容 */
    private String content;
    
    /** 扩展属性配置对象 */
    private ExtensionConfig extension;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
        parseExtension();
    }

    /**
     * 解析扩展配置属性
     * 业务需求：支持动态扩展消息属性配置
     */
    private void parseExtension() {
        if (content != null && content.startsWith("{")) {
            // 解析JSON格式的扩展配置
            this.extension = JSON.parseObject(content, ExtensionConfig.class);
        }
    }

    // 其他业务字段及getter/setter省略...
}

/**
 * 扩展配置基础类
 * 支持未来可能新增的配置项
 */
class ExtensionConfig {
    // 通用配置字段定义
}

/*
 * 业务背景：系统需要支持动态扩展消息配置属性
 * 开发人员误以为ExtensionConfig类可限制反序列化类型
 * 实际fastjson的parseObject方法存在autotype漏洞风险
 */