package cn.qx.types.common;

import cn.qx.types.enums.ResponseCode;
import cn.qx.types.exception.AppException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * JWT 令牌工具：管理面登录态签发与校验。
 * <p>算法 HMAC256；secret 与过期时长从 application.yml 的 login.* 配置注入。
 * <p>由 Spring 容器管理（@Component），不写静态字段，便于测试与配置刷新。
 */
@Slf4j
@Component
public class JwtUtils {

    /** 令牌签发者 */
    private static final String ISSUER = "llm-gateway";

    /** HMAC256 算法实例（secret 变更时重建） */
    private final Algorithm algorithm;

    /** 校验器（与 algorithm 绑定） */
    private final JWTVerifier verifier;

    /** 过期分钟数 */
    private final long expireMinutes;

    public JwtUtils(
            @Value("${login.jwt-secret:}") String secret,
            @Value("${login.jwt-expire-minutes:120}") long expireMinutes) {
        if (secret == null || secret.length() < 16) {
            throw new IllegalStateException("login.jwt-secret 未配置或长度不足 16 位");
        }
        this.algorithm = Algorithm.HMAC256(secret);
        this.verifier = JWT.require(algorithm).withIssuer(ISSUER).build();
        this.expireMinutes = expireMinutes;
    }

    /**
     * 为指定用户名签发令牌。
     *
     * @param username 登录用户名（写入 subject）
     * @return 已签名的 JWT 字符串
     */
    public String generate(String username) {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiresAt = Date.from(now.plus(expireMinutes, ChronoUnit.MINUTES));
        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(username)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .sign(algorithm);
    }

    /**
     * 校验并解析令牌，返回用户名。
     * <p>签名非法、过期、issuer 不匹配均抛 {@link AppException}（code=0401）。
     *
     * @param token Bearer 后的令牌字符串（不含 "Bearer " 前缀）
     * @return 令牌 subject（即登录用户名）
     */
    public String verify(String token) {
        if (token == null || token.isBlank()) {
            throw new AppException(ResponseCode.UNAUTHORIZED.getCode(), "缺少登录令牌");
        }
        try {
            DecodedJWT jwt = verifier.verify(token);
            return jwt.getSubject();
        } catch (JWTVerificationException e) {
            log.warn("JWT 校验失败: {}", e.getMessage());
            throw new AppException(ResponseCode.UNAUTHORIZED.getCode(), "登录令牌无效或已过期");
        }
    }

    /** 令牌过期分钟数（供日志/响应展示使用）。 */
    public long getExpireMinutes() {
        return expireMinutes;
    }
}
