package cn.qx.api;

import cn.qx.api.dto.login.LoginResult;

/**
 * 登录用例接口（api 根包，对齐「服务必须定义接口」约定）。
 */
public interface ILoginCase {

    /**
     * 用户名密码登录。
     * <p>失败（密码错误 / 账号锁定）抛 {@link cn.qx.types.exception.AppException}，code=0401。
     *
     * @param username 用户名
     * @param password 密码
     * @return 登录成功结果（JWT 令牌 + 用户名）
     */
    LoginResult login(String username, String password);
}
