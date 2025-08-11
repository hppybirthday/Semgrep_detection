package com.chatapp.service;

import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;

@Service
public class ChatService {

    @Autowired
    private ResourceLoader resourceLoader;

    private String baseDir;

    @PostConstruct
    public void init() {
        baseDir = "/var/chatapp/avatars";
    }

    public Resource getAvatarResource(String username) {
        String relativePath = buildUnsafePath(username);
        return resourceLoader.getResource("file:" + relativePath);
    }

    private String buildUnsafePath(String username) {
        // 构建路径时未充分校验输入
        String combined = baseDir + "/" + username + ".png";
        return FilenameUtils.normalize(combined);
    }
}