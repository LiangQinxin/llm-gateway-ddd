package cn.qx.trigger.http;

import cn.qx.api.ILoginCase;
import cn.qx.api.dto.login.LoginRequest;
import cn.qx.api.dto.login.LoginResult;
import cn.qx.api.response.Response;
import cn.qx.api.response.Responses;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 登录 Controller（管理面 /api/v1/login）。
 * <p>前端 axios baseURL=/api + url=/v1/login 实际请求 /api/v1/login。
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
public class LoginController {

    /** 登录用例 */
    @Resource
    private ILoginCase loginCase;

    /**
     * 用户名密码登录。
     *
     * @param request 登录请求体
     * @return 登录结果（JWT 令牌）
     */
    @PostMapping("/login")
    public Response<LoginResult> login(@RequestBody LoginRequest request) {
        log.info("登录请求: username={}", request.getUsername());
        return Responses.success(loginCase.login(request.getUsername(), request.getPassword()));
    }
}
