import java.io.*;
import java.net.*;
import java.util.regex.*;
import javax.tools.*;
import java.lang.reflect.*;

public class VulnerableWebCrawler {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java VulnerableWebCrawler <url>");
            return;
        }

        String targetUrl = args[0];
        String rawHtml = fetchUrlContent(targetUrl);
        
        // Vulnerable regex-based data extraction
        Pattern scriptPattern = Pattern.compile("<script.*?>([\\s\\S]*?)<\\/script>", Pattern.CASE_INSENSITIVE);
        Matcher scriptMatcher = scriptPattern.matcher(rawHtml);
        
        // Dynamic code generation for demo purposes
        StringBuilder generatedCode = new StringBuilder();
        generatedCode.append("public class GeneratedReport {\
");
        generatedCode.append("    public String renderContent() {\
");
        generatedCode.append("        return \\"<html><body><h1>Extracted Scripts:</h1><ul>\\" +
        
        while (scriptMatcher.find()) {
            String scriptContent = scriptMatcher.group(1).replace("\\"", "\\\\\\"");
            // Vulnerability: Direct injection of raw script content into HTML
            generatedCode.append(String.format("\\"<li>%s</li>\\" +
        ", scriptContent));
        }
        
        generatedCode.append("\\"</ul></body></html>\\";\
");
        generatedCode.append("    }\
");
        generatedCode.append("}\
");

        // Compile generated code at runtime
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        JavaFileManager fileManager = new ForwardingJavaFileManager<>(compiler.getStandardFileManager(diagnostics, null, null)) {
            public OutputStream getOutputStream(Location location, String className, Kind kind) {
                return new ByteArrayOutputStream();
            }
        };

        Iterable<? extends JavaFileObject> compilationUnits = Arrays.asList(new JavaSourceFromString("GeneratedReport", generatedCode.toString()));
        compiler.getTask(null, fileManager, diagnostics, null, null, compilationUnits).call();
        
        // Load and execute generated class
        Class<?> generatedClass = classLoader.loadClass("GeneratedReport");
        Object instance = generatedClass.getDeclaredConstructor().newInstance();
        Method method = generatedClass.getMethod("renderContent");
        
        // Output vulnerable HTML
        System.out.println((String) method.invoke(instance));
    }

    static String fetchUrlContent(String url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestProperty("User-Agent", "VulnerableCrawler/1.0");
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line).append("\
");
        }
        
        reader.close();
        return response.toString();
    }

    static class JavaSourceFromString extends SimpleJavaFileObject {
        final String code;

        JavaSourceFromString(String name, String code) {
            super(URI.create("string:///" + name.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
            this.code = code;
        }

        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return code;
        }
    }
}