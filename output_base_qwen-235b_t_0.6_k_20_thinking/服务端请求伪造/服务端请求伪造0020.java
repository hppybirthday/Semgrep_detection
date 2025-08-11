import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class ImageProcessorServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String imageUrl = request.getParameter("url");
        if (imageUrl == null || imageUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }

        try {
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 模拟图片处理
            int contentLength = connection.getContentLength();
            if (contentLength == -1 || contentLength > 1024 * 1024 * 5) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid content length");
                return;
            }

            InputStream inputStream = connection.getInputStream();
            byte[] imageData = readStream(inputStream, contentLength);
            
            // 设置响应头
            response.setContentType("image/jpeg");
            response.setContentLength(imageData.length);
            
            // 写出处理后的图片
            OutputStream outputStream = response.getOutputStream();
            outputStream.write(imageData);
            outputStream.flush();
            
        } catch (MalformedURLException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL format");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error fetching image");
        }
    }

    private byte[] readStream(InputStream input, int length) throws IOException {
        byte[] buffer = new byte[length];
        int bytesRead = 0;
        int offset = 0;
        
        while (offset < length) {
            bytesRead = input.read(buffer, offset, length - offset);
            if (bytesRead == -1) break;
            offset += bytesRead;
        }
        
        return buffer;
    }
}