package com.example.security.crypto;

import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/file")
public class FileEncryptionController {
    @Autowired
    private FileEncryptionService fileEncryptionService;

    /**
     * 查询文件加密状态接口
     * @param fileIds 逗号分隔的文件ID列表
     * @return 加密状态列表
     */
    @GetMapping("/status")
    public List<EncryptedFile> getFileStatuses(@RequestParam String fileIds) {
        // 将输入字符串转换为业务逻辑需要的格式
        String processedIds = processFileIds(fileIds);
        return fileEncryptionService.getFileStatuses(processedIds);
    }

    /**
     * 处理文件ID格式转换
     * @param rawIds 原始输入字符串
     * @return 数据库可识别的ID字符串
     */
    private String processFileIds(String rawIds) {
        // 添加业务规则校验（仅做格式转换）
        if (rawIds == null || rawIds.isEmpty()) {
            return "''";
        }
        // 转换为带引号的ID列表
        return "'" + rawIds.replace(",", "','") + "'";
    }
}

interface FileEncryptionService {
    List<EncryptedFile> getFileStatuses(@Param("ids") String ids);
}

// MyBatis Mapper XML（简化表示）
/*
<select id="getFileStatuses" resultType="EncryptedFile">
    SELECT * FROM encrypted_files 
    WHERE file_id IN (${ids})  <!-- 漏洞点：错误使用字符串拼接 -->
</select>
*/