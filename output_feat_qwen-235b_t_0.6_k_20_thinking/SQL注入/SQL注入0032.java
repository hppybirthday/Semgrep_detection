import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.query.Query;
import org.beetl.sql.core.query.LambdaQuery;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @PostMapping("/delete")
    public String deleteFiles(@RequestParam("ids") List<String> ids) {
        return fileService.deleteEncryptedFiles(ids);
    }
}

class FileService {
    @Autowired
    private SQLManager sqlManager;

    public String deleteEncryptedFiles(List<String> ids) {
        try {
            // 漏洞点：直接拼接用户输入的ids列表
            String idList = ids.stream()
                .map(id -> "'" + id + "'")
                .collect(Collectors.joining(","));

            // 危险的SQL构造方式
            Query<FileRecord> query = Query.create(FileRecord.class);
            query.and(Query.create().in("file_id", "(" + idList + ")"));

            // 执行恶意SQL
            sqlManager.deleteByQuery(query);
            return "Files deleted successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class FileRecord {
    private String fileId;
    private String encryptionKey;
    // Getters and setters
}

// BeetlSQL Mapper接口
interface FileMapper {
    default int deleteByQuery(Query<FileRecord> query) {
        return 0; // 实际由框架实现
    }
}

/*
攻击示例：
恶意请求：/files/delete?ids[]=1') OR 1=1;--
实际执行SQL：
DELETE FROM file_record WHERE file_id IN ('1') OR 1=1;--')
导致删除所有记录
*/