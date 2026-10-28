package cn.qx.domain.login.service;

/**
 * 登录风控领域服务：失败计数、短锁（1 分钟）与长锁（8 小时）判定。
 * <p>纯内存实现，单用户、单机部署场景足够。
 */
public interface ILoginService {

    /**
     * 若账号处于锁定状态，直接抛 {@link cn.qx.types.exception.AppException}（code=0401）。
     *
     * @param username 登录用户名
     */
    void assertNotLocked(String username);

    /**
     * 记录一次登录失败：清理窗口外旧记录、累加当前失败时间，
     * 命中阈值则升级短锁 / 长锁。
     *
     * @param username 登录用户名
     */
    void recordFailure(String username);

    /**
     * 登录成功：清空该用户名的所有失败记录与锁定状态。
     *
     * @param username 登录用户名
     */
    void recordSuccess(String username);
}
