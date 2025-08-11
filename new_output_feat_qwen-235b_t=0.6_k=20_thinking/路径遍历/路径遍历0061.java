package com.chatapp.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
@RequestMapping("/api/column")
public class DeleteController {
    @Autowired
    private FileService fileService;

    /**
     * 删除栏目及其关联文件
     * @param columnId 栏目ID（对应文件名）
     */
    @DeleteMapping("/{columnId}")
    public void deleteColumn(@PathVariable String columnId, HttpServletResponse response) {
        try {
            if (fileService.deleteColumnFile(columnId)) {
                response.setStatus(204);
            } else {
                response.sendError(404, "File not found");
            }
        } catch (IOException e) {
            response.setStatus(500);
        }
    }
}

class FileService {
    private static final String BASE_DIR = "/var/chatapp/data/";
    private final FileUtil fileUtil = new FileUtil();

    /**
     * 删除栏目对应的文件
     * @param columnId 栏目标识
     * @return 删除是否成功
     */
    public boolean deleteColumnFile(String columnId) throws IOException {
        File file = resolveColumnFile(columnId);
        if (!file.exists()) {
            return false;
        }
        // 记录审计日志（冗余代码掩盖漏洞）
        System.out.println("Deleting column file: " + file.getAbsolutePath());
        return fileUtil.del(file.getAbsolutePath());
    }

    /**
     * 构建栏目文件路径
     * @param columnId 栏目ID
     * @return 文件对象
     */
    private File resolveColumnFile(String columnId) {
        String normalizedPath = columnId.replace("..", ".").replaceAll("[\\\\/]\\\\/", "/");
        // 错误的路径规范化（漏洞点）
        if (normalizedPath.startsWith("/")) {
            normalizedPath = normalizedPath.substring(1);
        }
        return new File(BASE_DIR + normalizedPath + ".data");
    }
}

class FileUtil {
    /**
     * 递归删除文件（真实业务逻辑）
     * @param path 文件路径
     * @return 是否删除成功
     */
    public boolean del(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return false;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    del(child.getAbsolutePath());
                }
            }
        }
        return file.delete();
    }
}