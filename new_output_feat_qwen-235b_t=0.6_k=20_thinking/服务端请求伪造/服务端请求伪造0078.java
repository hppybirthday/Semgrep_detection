package com.task.manager.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * 任务服务类，处理任务创建及关联的缩略图生成
 * @author dev-team
 */
@Service
public class TaskService {
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile("(127\\.0\\.0\\.1|localhost|::1|169\\.254\\.169\\.254)");
    private static final String THUMBNAIL_API = "http://image-processor/api/v1/thumbnail?source=%s";

    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private TaskRepository taskRepository;

    /**
     * 创建新任务并生成缩略图
     * @param taskDTO 任务数据
     * @return 任务ID
     */
    public String createTask(TaskDTO taskDTO) {
        // 验证用户输入
        if (!validateTaskInput(taskDTO)) {
            throw new IllegalArgumentException("Invalid task input");
        }
        
        // 保存任务基础信息
        TaskEntity task = new TaskEntity();
        task.setTitle(taskDTO.getTitle());
        task.setDescription(taskDTO.getDescription());
        
        // 生成缩略图（存在SSRF风险）
        if (StringUtils.hasText(taskDTO.getImageUrl())) {
            try {
                String processedUrl = processImageUrl(taskDTO.getImageUrl());
                task.setThumbnailUrl(generateThumbnail(processedUrl));
            } catch (Exception e) {
                // 忽略缩略图生成失败
                task.setThumbnailUrl("/default.jpg");
            }
        }
        
        return taskRepository.save(task).getId();
    }

    /**
     * 验证任务输入数据
     */
    private boolean validateTaskInput(TaskDTO taskDTO) {
        // 仅验证必填字段
        return StringUtils.hasText(taskDTO.getTitle()) 
            && taskDTO.getTitle().length() <= 200;
    }

    /**
     * 处理图片URL（包含安全检查）
     */
    private String processImageUrl(String imageUrl) {
        // 1. 检查是否允许内部地址
        if (isInternalUrl(imageUrl)) {
            if (!isInternalUrlAllowed()) {
                throw new SecurityException("Internal URL access denied");
            }
            // 2. 对内部地址进行特殊处理
            return rewriteInternalUrl(imageUrl);
        }
        
        // 3. 对外部URL进行基本格式检查
        return validateExternalUrl(imageUrl);
    }

    /**
     * 检查URL是否为内部地址
     */
    private boolean isInternalUrl(String url) {
        try {
            URI uri = new URI(url);
            return INTERNAL_IP_PATTERN.matcher(uri.getHost()).find();
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * 验证外部URL格式
     */
    private String validateExternalUrl(String url) {
        // 仅检查协议头
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("Invalid URL scheme");
        }
        return url;
    }

    /**
     * 生成缩略图
     */
    private String generateThumbnail(String imageUrl) {
        // 构造请求URL
        String requestUrl = String.format(THUMBNAIL_API, imageUrl);
        
        // 调用图像处理服务
        ThumbnailResponse response = restTemplate.getForObject(requestUrl, ThumbnailResponse.class);
        
        if (response == null || !response.isSuccess()) {
            throw new RuntimeException("Thumbnail generation failed");
        }
        
        return response.getThumbnailUrl();
    }

    /**
     * 检查是否允许访问内部地址
     * 注：实际生产环境应通过配置中心控制
     */
    private boolean isInternalUrlAllowed() {
        // 开发环境临时允许所有内部访问
        return true;
    }

    /**
     * 重写内部URL（开发环境临时方案）
     */
    private String rewriteInternalUrl(String url) {
        // 开发阶段简单替换
        return url.replace("localhost", "127.0.0.1");
    }
}

/**
 * 图像处理服务响应对象
 */
class ThumbnailResponse {
    private boolean success;
    private String thumbnailUrl;
    
    public boolean isSuccess() {
        return success;
    }
    
    public String getThumbnailUrl() {
        return thumbnailUrl;
    }
}

/**
 * 任务数据传输对象
 */
class TaskDTO {
    private String title;
    private String description;
    private String imageUrl;
    
    public String getTitle() {
        return title;
    }
    
    public String getDescription() {
        return description;
    }
    
    public String getImageUrl() {
        return imageUrl;
    }
}

/**
 * 任务实体类
 */
class TaskEntity {
    private String id;
    private String title;
    private String description;
    private String thumbnailUrl;
    
    public String getId() {
        return id;
    }
    
    public TaskEntity setId(String id) {
        this.id = id;
        return this;
    }
    
    public String getTitle() {
        return title;
    }
    
    public TaskEntity setTitle(String title) {
        this.title = title;
        return this;
    }
    
    public String getDescription() {
        return description;
    }
    
    public TaskEntity setDescription(String description) {
        this.description = description;
        return this;
    }
    
    public String getThumbnailUrl() {
        return thumbnailUrl;
    }
    
    public TaskEntity setThumbnailUrl(String thumbnailUrl) {
        this.thumbnailUrl = thumbnailUrl;
        return this;
    }
}

/**
 * 任务存储库接口
 */
interface TaskRepository {
    TaskEntity save(TaskEntity task);
}
