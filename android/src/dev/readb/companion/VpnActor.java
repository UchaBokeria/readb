package dev.readb.companion;

import java.util.concurrent.*;

/** One ordered backend lane across service replacements; stale instance callbacks are dropped. */
final class VpnActor {
    private static final ScheduledExecutorService WORKER = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "ReadbVpn"); thread.setDaemon(true); return thread;
    });
    private volatile boolean closed;
    private ScheduledFuture<?> periodic;
    void initialize(Runnable action) { WORKER.execute(action); }
    void execute(Runnable action) {
        if (!closed) WORKER.execute(() -> { if (!closed) action.run(); });
    }
    synchronized void repeat(Runnable action, long seconds) {
        if (!closed) periodic = WORKER.scheduleWithFixedDelay(() -> { if (!closed) action.run(); }, 0, seconds, TimeUnit.SECONDS);
    }
    synchronized void close(Runnable teardown) {
        if (closed) return;
        closed = true;
        if (periodic != null) periodic.cancel(false);
        WORKER.execute(teardown);
    }
}
