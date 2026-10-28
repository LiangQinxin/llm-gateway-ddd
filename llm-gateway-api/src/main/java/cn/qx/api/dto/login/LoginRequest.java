package cn.qx.api.dto.login;

import lombok.Data;

import java.io.Serializable;

/**
 * 登录请求体：仅用户名 + 密码。
 */
@Data
public class LoginRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 登录用户名 */
    private String username;

    /** 登录密码 */
    private String password;
}
