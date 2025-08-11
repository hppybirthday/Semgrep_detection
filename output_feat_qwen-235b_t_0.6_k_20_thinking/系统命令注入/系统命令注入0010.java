import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

public class DataCleanerFilter implements Filter {
    private static final String CLEAN_SCRIPT = "/usr/local/bin/clean_log.sh";
    private static final String LOG_DIR = "/var/log/app/";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String logFile = httpRequest.getParameter("cmd_");
            PrintWriter out = response.getWriter();
            
            if (logFile == null || logFile.isEmpty()) {
                out.println("Error: Missing log file parameter");
                return;
            }

            // Vulnerable command construction
            String[] cmd = {
                "/bin/sh",
                "-c",
                CLEAN_SCRIPT + " " + LOG_DIR + logFile
            };

            try {
                Process process = Runtime.getRuntime().exec(cmd);
                int exitCode = process.waitFor();
                
                if (exitCode == 0) {
                    out.println("Data cleaning completed successfully");
                } else {
                    out.println("Error: Data cleaning failed with code " + exitCode);
                }
            } catch (Exception e) {
                out.println("Critical error: " + e.getMessage());
                e.printStackTrace(out);
            }
    }

    @Override
    public void destroy() {
        // Cleanup code
    }
}