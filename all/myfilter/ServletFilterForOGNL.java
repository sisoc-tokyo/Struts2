package myfilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.regex.Pattern;

public class ServletFilterForOGNL implements javax.servlet.Filter {
	private static final String SIGNATURE_OGNL = 
			"OgnlContext|OgnlUtil|#context|@DEFAULT_MEMBER_ACCESS|#_memberAccess|java.lang.ProcessBuilder|java.lang.Runtime|%23context|%40DEFAULT_MEMBER_ACCESS|%23_memberAccess|java%2elang%2eProcessBuilder|java%2elang%2eRuntime";
	private static final String ERROR_INVALID_REQUEST = "BlockedByServletFilterForOGNL.Please press back button.";
	private static final String filterName="ServletFilterForOGNL";
	private FilterConfig filterConfig;
	private Pattern p = Pattern.compile(SIGNATURE_OGNL);

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws java.io.IOException, javax.servlet.ServletException {
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		// URL
		String uri = httpRequest.getRequestURI();

		// Query
		String query = httpRequest.getQueryString();

		// body
		//StringBuilder body = new StringBuilder("");
		String body="";
		httpRequest.setCharacterEncoding("UTF-8");
		   Enumeration names = httpRequest.getParameterNames();
		    while (names.hasMoreElements()){
		      String name = (String)names.nextElement();
		      String vals[] = request.getParameterValues(name);
		      if (vals != null){
		        for (String s : vals){
		          //body.append(vals[i]);
		          body+=s;
		        }
		      }
		    }
		//System.out.println("body:" +body );

		try{
		// header
		Enumeration<String> headernames = httpRequest.getHeaderNames();
		while (headernames.hasMoreElements()) {
			String name = (String) headernames.nextElement();
			Enumeration<String> headervals = httpRequest.getHeaders(name);
			while (headervals.hasMoreElements()) {
				String value = (String) headervals.nextElement();
				if (p.matcher(value).find()) {
					System.out.println(filterName+":Malicious header:" + name + ": " + value);
					throw new ServletException(ERROR_INVALID_REQUEST);
				}
			}
		}
		if (p.matcher(uri).find()) {
			System.out.println(filterName+":Malicious URI:" + uri);
			throw new ServletException(ERROR_INVALID_REQUEST);
		} else if (null != query && p.matcher(query).find()) {
			System.out.println(filterName+":Malicious query:" + query);
			throw new ServletException(ERROR_INVALID_REQUEST);
		} else if (p.matcher(body).find()) {
			System.out.println(filterName+":Malicious body:" + body);
			throw new ServletException(ERROR_INVALID_REQUEST);
		}
		} catch (ServletException se){
			throw(se);
		}
		chain.doFilter(request, response);
	}

	@Override
	public void init(final FilterConfig filterConfig) {
		this.filterConfig = filterConfig;
	}

	@Override
	public void destroy() {
		filterConfig = null;
	}
}