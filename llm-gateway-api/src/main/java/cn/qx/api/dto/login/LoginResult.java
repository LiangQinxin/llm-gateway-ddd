package cn.qx.api.dto.login;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 登录成功响应：JWT 令牌 + 用户名。
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResult implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 已签名的 JWT 令牌（前端后续请求放 Authorization: Bearer 头） */
    private String token;

    /** 登录用户名 */
    private String username;

    /** 过期分钟数（前端展示用） */
    private long expireMinutes;
}
