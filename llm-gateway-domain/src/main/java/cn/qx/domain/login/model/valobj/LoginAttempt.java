package cn.qx.domain.login.model.valobj;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * 登录失败状态值对象（单机内存保存，不持久化）。
 * <p>记录该用户名在最近滑动窗口内的失败时间戳与两个锁截止时间。
 */
@Getter
@Setter
public class LoginAttempt {

    /** 最近失败时间戳队列（毫秒，仅保留窗口内的） */
    private Deque<Long> recentErrorAtMillis = new ArrayDeque<>();

    /** 短锁（1 分钟）截止时间戳；0 表示无短锁 */
    private long shortLockUntilMillis;

    /** 长锁（8 小时）截止时间戳；0 表示无长锁 */
    private long longLockUntilMillis;
}
