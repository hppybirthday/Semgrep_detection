import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @GetMapping
    public List<File> listFiles(@RequestParam String sort, @RequestParam String order) {
        return fileService.getSortedFiles(sort, order);
    }
}

@Service
class FileService {
    @Autowired
    private FileMapper fileMapper;

    public List<File> getSortedFiles(String sort, String order) {
        return fileMapper.selectSortedFiles(sort, order);
    }
}

@Mapper
interface FileMapper {
    @Select("SELECT * FROM files ORDER BY ${sort} ${order}")
    List<File> selectSortedFiles(String sort, String order);
}

@Data
class File {
    private Long id;
    private String name;
    private String encryptedData;
}

// MyBatis XML映射文件（实际应包含在resources目录下）
/*
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="FileMapper">
  <select id="selectSortedFiles" resultType="File">
    SELECT * FROM files
    ORDER BY ${sort} ${order}
  </select>
</mapper>
*/