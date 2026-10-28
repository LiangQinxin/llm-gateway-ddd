package cn.qx.trigger.filter;

import cn.qx.types.common.JwtUtils;
import cn.qx.types.enums.ResponseCode;
import cn.qx.types.exception.AppException;
import com.alibaba.fastjson2.JSONObject;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 管理面 JWT 鉴权过滤器：优先级最高，在所有业务 Filter 之前执行。
 * <p>拦截 /api/** 管理面请求，校验 Authorization: Bearer &lt;token&gt;；
 * 登录接口 /api/v1/login、OPTIONS 预检、/health 放行；
 * 数据面 /v1/** 与 /mcp 不在本过滤器管辖范围（由 {@link ApiKeyFilter} 处理）。
 * <p>注意：Filter 执行在 DispatcherServlet 之前，GlobalExceptionHandler 捕不到此处异常，
 * 因此鉴权失败直接写 401 JSON 响应。
 */
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** 请求属性：登录用户名（Controller 后续可读取） */
    public static final String LOGIN_USERNAME_ATTRIBUTE = JwtAuthenticationFilter.class.getName() + ".loginUsername";

    /** Bearer 前缀 */
    private static final String BEARER_PREFIX = "Bearer ";

    /** 登录接口白名单路径 */
    private static final String LOGIN_PATH = "/api/v1/login";

    /** 健康检查白名单 */
    private static final String HEALTH_PATH = "/health";
    /** 管理面健康检查白名单（前端探针用） */
    private static final String API_HEALTH_PATH = "/api/v1/health";

    /** JWT 工具 */
    @Resource
    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // CORS 预检直接放行
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();

        // 白名单：登录接口、健康检查
        if (LOGIN_PATH.equals(path) || HEALTH_PATH.equals(path) || API_HEALTH_PATH.equals(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 仅拦截管理面 /api/**；其他路径（数据面 /v1/、/mcp 等）放行给后续 Filter
        if (path == null || !path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            writeUnauthorized(response, "缺少登录令牌");
            return;
        }
        String token = authorization.substring(BEARER_PREFIX.length()).trim();
        try {
            String username = jwtUtils.verify(token);
            request.setAttribute(LOGIN_USERNAME_ATTRIBUTE, username);
            filterChain.doFilter(request, response);
        } catch (AppException e) {
            log.warn("管理面 JWT 鉴权失败: path={}, info={}", path, e.getInfo());
            writeUnauthorized(response, e.getInfo());
        }
    }

    /** 写 401 JSON 响应，结构与前端约定的 {code, info, data} 对齐。 */
    private static void writeUnauthorized(HttpServletResponse response, String info) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        JSONObject body = new JSONObject();
        body.put("code", ResponseCode.UNAUTHORIZED.getCode());
        body.put("info", info);
        body.put("data", null);
        response.getWriter().write(body.toJSONString());
    }
}
