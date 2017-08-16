package myfilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Enumeration;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
 
public class ServletFilterForOGNL implements javax.servlet.Filter
{
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
        
        Enumeration headernames = httpRequest.getHeaderNames();
        while (headernames.hasMoreElements()){
          String name = (String)headernames.nextElement();
          Enumeration headervals = httpRequest.getHeaders(name);
          while (headervals.hasMoreElements()){
            String value = (String)headervals.nextElement();
            if(p.matcher(value).find()){
            	System.out.println("Malicious request header:"+name+": "+value);
            	throw new ServletException(ERROR_INVALID_REQUEST);
            }
          }
        }
        if (p.matcher(uri).find()){
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