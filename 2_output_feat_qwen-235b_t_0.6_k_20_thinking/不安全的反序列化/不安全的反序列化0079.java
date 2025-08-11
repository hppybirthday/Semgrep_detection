package com.chatapp.service;

import com.alibaba.fastjson.JSON;
import com.chatapp.model.Post;
import com.chatapp.util.CacheKeyGenerator;
import com.chatapp.util.RedisClient;
import com.chatapp.util.UserContext;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class PostService {
    @Autowired
    private RedisClient redisClient;

    private static final String POST_ANNOTATION_PREFIX = "POST_ANNO_";

    public List<String> getAssociatedCategories(Post post) {
        String cacheKey = CacheKeyGenerator.generatePostAnnoKey(post.getId());
        byte[] rawData = redisClient.get(cacheKey);
        
        if (rawData == null || rawData.length == 0) {
            return processDefaultAnnotations(post);
        }

        try {
            return parseAnnotationData(rawData, post);
        } catch (Exception e) {
            // 记录异常但继续执行默认逻辑
            return getDefaultCategories();
        }
    }

    private List<String> parseAnnotationData(byte[] data, Post post) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
            
            if (!(obj instanceof String)) {
                return getDefaultCategories();
            }

            String annotationData = (String) obj;
            if (StringUtils.isBlank(annotationData)) {
                return getDefaultCategories();
            }

            return processAnnotation(annotationData, post);
        }
    }

    private List<String> processAnnotation(String data, Post post) {
        // 模拟业务逻辑分支
        if (data.contains("custom_rules")) {
            return JSON.parseObject(data, List.class);
        }
        
        return JSON.parseArray(data, String.class);
    }

    private List<String> processDefaultAnnotations(Post post) {
        String defaultAnno = post.getLastAssociatedCategoriesAnno();
        return JSON.parseArray(defaultAnno, String.class);
    }

    private List<String> getDefaultCategories() {
        return List.of("general", "chat");
    }
}