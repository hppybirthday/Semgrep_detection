import java.sql.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileEncryptionController {
    private final FileService fileService;

    public FileEncryptionController(FileService fileService) {
        this.fileService = fileService;
    }

    @DeleteMapping("/{ids}")
    public ResponseEntity<String> deleteEncryptedFiles(@PathVariable String ids) {
        try {
            fileService.deleteFileRecords(ids);
            return ResponseEntity.ok("Files deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing request");
        }
    }
}

@Service
class FileService {
    private final FileMapper fileMapper;

    public FileService(FileMapper fileMapper) {
        this.fileMapper = fileMapper;
    }

    public void deleteFileRecords(String ids) {
        fileMapper.deleteFileRecords(ids);
    }
}

@Mapper
interface FileMapper {
    @Select({"<script>",
      "DELETE FROM encrypted_files WHERE id IN (${ids});",
      "</script>"})
    void deleteFileRecords(String ids);
}

// 模拟加密文件实体
class EncryptedFile {
    private int id;
    private String encryptedData;
    private String encryptionKey;
    // Getters and setters
}

// 数据库初始化脚本（简化版）
/*
CREATE TABLE encrypted_files (
    id INT PRIMARY KEY,
    encrypted_data TEXT,
    encryption_key VARCHAR(255)
);
*/