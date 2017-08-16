package myfilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
 
public class ServletFilterForOGNL implements javax.servlet.Filter
{
	private static final String MULTIPART = "multipart/";
	private static final String CONTENT_TYPE = "Content-Type";
	private static final String SIGNATURE_OGNL = "OgnlContext|OgnlUtil|#context";
	private static final String ERROR_INVALID_REQUEST = "Invalid request detected!";
	private FilterConfig filterConfig;
 
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
           FilterChain chain) 
           throws java.io.IOException, javax.servlet.ServletException
    {

        System.out.println("Servlet Filter: "+this.getClass().getName()+"Called.");
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String contentType = httpRequest.getHeader(CONTENT_TYPE);
        String uri = httpRequest.getRequestURI();
        
        BufferedReader reader = null;
        String body = "";
        try{
        	reader = httpRequest.getReader();
        	Stream<String> lines = reader.lines();
        	body = lines.collect(Collectors.joining("\r\n"));
        } catch (IOException e) {
        	// skip filter
        	e.printStackTrace();
        	chain.doFilter(request, response);
        } finally{
        	reader.close();
        }
        
        Pattern p = Pattern.compile(SIGNATURE_OGNL);
        
        if (contentType!=null && !contentType.toLowerCase(Locale.ENGLISH).startsWith(MULTIPART) && 
        		p.matcher(contentType).find()){
        	System.out.println("Malicious Content-Type:"+contentType);
        	throw new ServletException(ERROR_INVALID_REQUEST);
        } else if (p.matcher(uri).find()){
        	System.out.println("Malicious URI:"+uri);
        	throw new ServletException(ERROR_INVALID_REQUEST);
        } else if (p.matcher(body).find()){
        	System.out.println("Malicious Request body:"+body);
        	throw new ServletException(ERROR_INVALID_REQUEST);
        }
        chain.doFilter(request, response);
    }
 
    @Override
    public void init(final FilterConfig filterConfig)
    {
        this.filterConfig = filterConfig;
    }
 
    @Override
    public void destroy()
    {
        filterConfig = null;
    }
}