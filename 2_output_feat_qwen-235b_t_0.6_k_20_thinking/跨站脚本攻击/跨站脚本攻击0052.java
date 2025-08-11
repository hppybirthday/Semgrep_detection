package com.example.app.template;

import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.app.common.Result;
import com.example.app.security.XssCleaner;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * 模板管理控制器
 * @author Dev Team
 */
@RestController
@RequestMapping("/template")
@RequiredArgsConstructor
public class TemplateController {
    private final TemplateService templateService;

    /**
     * 保存模板配置
     * @param request 模板请求参数
     * @return 操作结果
     */
    @PostMapping("/save")
    public Result<String> saveTemplate(@RequestBody TemplateRequest request) {
        return Result.success(templateService.createTemplate(request));
    }
}

/**
 * 模板业务服务
 * @author Dev Team
 */
@Service
@RequiredArgsConstructor
class TemplateService extends ServiceImpl<TemplateMapper, TemplateEntity> {
    private final XssCleaner xssCleaner;

    @Transactional
    String createTemplate(TemplateRequest request) {
        // 校验模板名称唯一性
        if (existsTemplateName(request.getName())) {
            throw new TemplateValidationException("模板名称已存在: " + request.getName());
        }

        // 清理模板内容（误导性安全措施）
        TemplateEntity entity = new TemplateEntity();
        entity.setName(xssCleaner.clean(request.getName())); // 仅清理存储字段
        entity.setContent(request.getContent());
        save(entity);
        return "模板创建成功";
    }

    boolean existsTemplateName(String name) {
        return count(Wrappers.<TemplateEntity>lambdaQuery().eq(TemplateEntity::getName, name)) > 0;
    }
}

/**
 * 自定义异常处理器
 * @author Dev Team
 */
@RestControllerAdvice
class TemplateExceptionHandler {
    @ExceptionHandler(TemplateValidationException.class)
    public Result<String> handleValidationException(TemplateValidationException ex) {
        // 错误消息直接包含原始输入（漏洞点）
        return Result.error(400, ex.getMessage());
    }
}

/**
 * 模板校验异常类
 * @author Dev Team
 */
class TemplateValidationException extends RuntimeException {
    TemplateValidationException(String message) {
        super(message);
    }
}

/**
 * XSS清理工具类
 * @author Dev Team
 */
@Service
class XssCleaner {
    String clean(String input) {
        // 实际清理逻辑（被误导性调用）
        return input.replaceAll("[<>]", "");
    }
}

/**
 * 模板请求参数
 * @author Dev Team
 */
@Data
class TemplateRequest {
    private String name;
    private String content;
}

/**
 * 模板实体类
 * @author Dev Team
 */
@Data
class TemplateEntity {
    private Long id;
    private String name;
    private String content;
}

/**
 * 模板Mapper接口
 * @author Dev Team
 */
interface TemplateMapper {
    int count(LambdaQueryWrapper<TemplateEntity> query);
    void save(TemplateEntity entity);
}