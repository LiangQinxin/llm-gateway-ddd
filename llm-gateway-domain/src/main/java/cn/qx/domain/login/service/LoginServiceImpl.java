package cn.qx.domain.login.service;

import cn.qx.domain.login.model.valobj.LoginAttempt;
import cn.qx.types.enums.ResponseCode;
import cn.qx.types.exception.AppException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录风控领域服务实现：单机内存 ConcurrentHashMap。
 * <p>规则：
 * <ul>
 *   <li>滑动 5 分钟窗口内累计失败 ≥ 3 次 → 短锁 1 分钟；</li>
 *   <li>滑动 5 分钟窗口内累计失败 ≥ 8 次 → 长锁 8 小时；</li>
 *   <li>登录成功立即清空该用户名的所有状态。</li>
 * </ul>
 */
@Slf4j
@Service
public class LoginServiceImpl implements ILoginService {

    /** 短锁阈值：窗口内失败次数达到即锁 */
    private static final int SHORT_LOCK_THRESHOLD = 3;

    /** 短锁时长：1 分钟（毫秒） */
    private static final long SHORT_LOCK_DURATION_MILLIS = 60_000L;

    /** 长锁阈值：窗口内失败次数达到即锁 */
    private static final int LONG_LOCK_THRESHOLD = 8;

    /** 长锁时长：8 小时（毫秒） */
    private static final long LONG_LOCK_DURATION_MILLIS = 8 * 3600_000L;

    /** 滑动统计窗口：5 分钟（毫秒） */
    private static final long WINDOW_MILLIS = 5 * 60_000L;

    /** 用户名 → 失败状态 */
    private final ConcurrentHashMap<String, LoginAttempt> attempts = new ConcurrentHashMap<>();

    @Override
    public void assertNotLocked(String username) {
        long now = System.currentTimeMillis();
        LoginAttempt attempt = attempts.get(username);
        if (attempt == null) {
            return;
        }
        if (attempt.getLongLockUntilMillis() > now) {
            long remainMinutes = (attempt.getLongLockUntilMillis() - now + 59_999L) / 60_000L;
            throw new AppException(ResponseCode.UNAUTHORIZED.getCode(),
                    "账号已被锁定，请 " + (remainMinutes / 60) + " 小时 " + (remainMinutes % 60) + " 分钟后重试");
        }
        if (attempt.getShortLockUntilMillis() > now) {
            long remainSeconds = (attempt.getShortLockUntilMillis() - now + 999L) / 1000L;
            throw new AppException(ResponseCode.UNAUTHORIZED.getCode(),
                    "密码错误次数过多，请 " + remainSeconds + " 秒后重试");
        }
    }

    @Override
    public void recordFailure(String username) {
        long now = System.currentTimeMillis();
        LoginAttempt attempt = attempts.compute(username, (k, v) -> {
            LoginAttempt current = v == null ? new LoginAttempt() : v;
            Deque<Long> queue = current.getRecentErrorAtMillis();
            // 清理窗口外旧记录
            while (!queue.isEmpty() && queue.peekFirst() < now - WINDOW_MILLIS) {
                queue.pollFirst();
            }
            queue.addLast(now);
            // 命中长锁阈值：直接长锁
            if (queue.size() >= LONG_LOCK_THRESHOLD) {
                current.setLongLockUntilMillis(now + LONG_LOCK_DURATION_MILLIS);
                current.setShortLockUntilMillis(0L);
            } else if (queue.size() >= SHORT_LOCK_THRESHOLD) {
                // 命中短锁阈值：滚动续期 1 分钟
                current.setShortLockUntilMillis(now + SHORT_LOCK_DURATION_MILLIS);
            }
            return current;
        });
        log.warn("登录失败记录: username={}, windowCount={}, shortLockUntil={}, longLockUntil={}",
                username,
                attempt.getRecentErrorAtMillis().size(),
                attempt.getShortLockUntilMillis(),
                attempt.getLongLockUntilMillis());
    }

    @Override
    public void recordSuccess(String username) {
        attempts.remove(username);
        log.info("登录成功，已清空失败状态: username={}", username);
    }
}
