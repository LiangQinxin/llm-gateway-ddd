package cn.qx.cases.login;

import cn.qx.api.ILoginCase;
import cn.qx.api.dto.login.LoginResult;
import cn.qx.domain.login.service.ILoginService;
import cn.qx.types.common.JwtUtils;
import cn.qx.types.enums.ResponseCode;
import cn.qx.types.exception.AppException;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * 登录用例：硬编码账号校验 + 风控计数 + JWT 签发。
 * <p>账号从 application.yml 的 login.username / login.password 注入。
 */
@Slf4j
@Service
public class LoginCase implements ILoginCase {

    /** 配置中的合法用户名 */
    @Value("${login.username:}")
    private String configuredUsername;

    /** 配置中的合法密码 */
    @Value("${login.password:}")
    private String configuredPassword;

    /** 登录风控领域服务 */
    @Resource
    private ILoginService loginService;

    /** JWT 工具 */
    @Resource
    private JwtUtils jwtUtils;

    @Override
    public LoginResult login(String username, String password) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new AppException(ResponseCode.ILLEGAL_PARAMETER.getCode(), "用户名或密码不能为空");
        }
        // 1. 锁定状态预检（锁定期间即使密码正确也拒绝）
        loginService.assertNotLocked(username);

        // 2. 用户名密码比对
        boolean matched = Objects.equals(configuredUsername, username)
                && Objects.equals(configuredPassword, password);
        if (!matched) {
            // 3. 失败：记录一次并抛错
            loginService.recordFailure(username);
            throw new AppException(ResponseCode.UNAUTHORIZED.getCode(), "用户名或密码错误");
        }

        // 4. 成功：清空失败状态、签发 JWT
        loginService.recordSuccess(username);
        String token = jwtUtils.generate(username);
        log.info("登录成功: username={}", username);
        return LoginResult.builder()
                .token(token)
                .username(username)
                .expireMinutes(jwtUtils.getExpireMinutes())
                .build();
    }
}
