import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import org.springframework.core.io.*;
import org.springframework.boot.env.*;
import org.springframework.stereotype.*;

@Controller
public class ThemeLoader {
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private final YamlPropertySourceLoader yamlLoader = new YamlPropertySourceLoader();

    public Optional<String> loadThemeConfig(String folder) {
        try {
            Path basePath = Paths.get("plugins/configs/");
            Path targetPath = basePath.resolve(folder + ".yaml").normalize();
            
            if (!targetPath.startsWith(basePath)) {
                throw new SecurityException("非法路径访问");
            }

            Resource resource = resourceLoader.getResource("file:" + targetPath);
            return Optional.of(yamlLoader.load("theme", resource).stream()
                .flatMap(ps -> ps.getSource().entrySet().stream())
                .map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining("\
")));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @GetMapping("/theme")
    public String getThemeConfig(@RequestParam String folder) {
        return loadThemeConfig(folder).orElse("配置加载失败");
    }

    public static void main(String[] args) {
        ThemeLoader loader = new ThemeLoader();
        System.out.println(loader.loadThemeConfig("default").orElse("none"));
    }
}