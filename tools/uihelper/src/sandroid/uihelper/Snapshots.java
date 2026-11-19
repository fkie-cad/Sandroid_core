package sandroid.uihelper;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Tap-time strategy (b): keep recent full copies of the UI so a tap can be
 * resolved against the UI as it was <em>at</em> the tap, even when the host asks
 * after the app has already navigated away.
 *
 * <p>Policy: every UI-changing a11y event marks the cache dirty; a snapshot is
 * taken once the UI has been quiet for {@code quietMs}, or at the latest
 * {@code maxStaleMs} after the first unsnapshotted change (busy screens), and
 * never more often than {@code max(minIntervalMs, min(1 s, 1.5 x last snapshot duration))}.
 * A small ring of snapshots is kept, plus a ring of change timestamps so a reply
 * can say whether the UI changed between the snapshot and the queried instant.
 */
final class Snapshots {
    interface Capturer {
        Snap capture() throws Exception;
    }

    static final class Snap {
        long seq;
        double startMs;
        double endMs;
        boolean changedDuring;
        boolean truncated;
        int nodes;
        int screenW;
        int screenH;
        int rotation;
        List<Tree.SWindow> windows;
    }

    volatile boolean enabled = true;
    volatile double quietMs = 150;
    volatile double maxStaleMs = 1200;
    volatile double minIntervalMs = 250;
    volatile int ringSize = 4;

    private final Capturer capturer;
    private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "uihelper-snap");
        t.setDaemon(true);
        return t;
    });

    private final Object lock = new Object();
    private final ArrayDeque<Snap> ring = new ArrayDeque<>();
    private final double[] changes = new double[1024];
    private long changeSeq; // total changes seen
    private double lastChangeMs = -1;
    private double firstDirtyMs = -1; // first change not covered by a snapshot
    private boolean scheduled;
    private boolean running;
    private double lastSnapEndMs = -1;
    private double lastTookMs;
    private long snapSeq;
    long taken;
    double tookTotalMs;
    long failures;
    private int consecutiveFailures;

    Snapshots(Capturer capturer) {
        this.capturer = capturer;
    }

    /** A UI-changing event happened at device-monotonic time {@code tMs}. */
    void onChange(double tMs) {
        synchronized (lock) {
            changes[(int) (changeSeq % changes.length)] = tMs;
            changeSeq++;
            lastChangeMs = Math.max(lastChangeMs, tMs);
            if (firstDirtyMs < 0) {
                firstDirtyMs = tMs;
            }
            scheduleLocked(quietMs);
        }
    }

    /** Force a snapshot soon (startup, enable, config change). */
    void kick() {
        synchronized (lock) {
            if (firstDirtyMs < 0) {
                firstDirtyMs = Main.monoMs();
            }
            scheduleLocked(0);
        }
    }

    private void scheduleLocked(double delayMs) {
        if (!enabled || scheduled || running) {
            return;
        }
        scheduled = true;
        exec.schedule(this::check, (long) Math.max(0, delayMs), TimeUnit.MILLISECONDS);
    }

    private void check() {
        double now = Main.monoMs();
        synchronized (lock) {
            scheduled = false;
            if (!enabled || firstDirtyMs < 0) {
                return;
            }
            double quietFor = now - lastChangeMs;
            // Back off after slow snapshots, but a slow one taken during an app launch
            // must not delay the next (now cheap) one for seconds: cap the back-off.
            double minGap = Math.max(minIntervalMs, Math.min(1000, 1.5 * lastTookMs));
            double wait = 0;
            if (quietFor < quietMs && now - firstDirtyMs < maxStaleMs) {
                wait = Math.max(wait, Math.min(quietMs - quietFor, maxStaleMs - (now - firstDirtyMs)));
            }
            if (lastSnapEndMs >= 0 && now - lastSnapEndMs < minGap) {
                wait = Math.max(wait, minGap - (now - lastSnapEndMs));
            }
            if (wait > 0) {
                scheduleLocked(wait);
                return;
            }
            running = true;
            firstDirtyMs = -1;
        }
        long seqAtStart;
        synchronized (lock) {
            seqAtStart = changeSeq;
        }
        Snap s = null;
        try {
            s = capturer.capture();
        } catch (Throwable t) {
            failures++;
        }
        synchronized (lock) {
            running = false;
            double end = Main.monoMs();
            lastSnapEndMs = end;
            if (s != null) {
                s.seq = ++snapSeq;
                s.changedDuring = changeSeq != seqAtStart;
                lastTookMs = s.endMs - s.startMs;
                taken++;
                tookTotalMs += lastTookMs;
                ring.addLast(s);
                while (ring.size() > Math.max(1, ringSize)) {
                    ring.removeFirst();
                }
            }
            if (changeSeq != seqAtStart && firstDirtyMs < 0) {
                firstDirtyMs = lastChangeMs;
            }
            if (s == null) {
                // Not connected / transient failure: retry with backoff (a reconnect kicks us anyway).
                consecutiveFailures++;
                if (firstDirtyMs < 0) {
                    firstDirtyMs = end;
                }
                scheduleLocked(Math.min(5000, 250.0 * (1 << Math.min(consecutiveFailures, 5))));
                return;
            }
            consecutiveFailures = 0;
            if (firstDirtyMs >= 0) {
                scheduleLocked(quietMs);
            }
        }
    }

    /** Newest snapshot that started at or before {@code tMs}. */
    Snap at(double tMs) {
        synchronized (lock) {
            Snap best = null;
            for (Snap s : ring) {
                if (s.startMs <= tMs) {
                    best = s;
                }
            }
            return best;
        }
    }

    Snap latest() {
        synchronized (lock) {
            return ring.peekLast();
        }
    }

    /** Number of change events in (fromMs, toMs] and the first one's time. */
    double[] changesBetween(double fromMs, double toMs) {
        synchronized (lock) {
            int n = 0;
            double first = -1;
            long lo = Math.max(0, changeSeq - changes.length);
            for (long i = lo; i < changeSeq; i++) {
                double c = changes[(int) (i % changes.length)];
                if (c > fromMs && c <= toMs) {
                    n++;
                    if (first < 0 || c < first) {
                        first = c;
                    }
                }
            }
            return new double[] {n, first};
        }
    }

    void clear() {
        synchronized (lock) {
            ring.clear();
        }
    }

    int size() {
        synchronized (lock) {
            return ring.size();
        }
    }

    double lastTookMs() {
        synchronized (lock) {
            return lastTookMs;
        }
    }

    int nodesHeld() {
        synchronized (lock) {
            int n = 0;
            for (Iterator<Snap> it = ring.iterator(); it.hasNext(); ) {
                n += it.next().nodes;
            }
            return n;
        }
    }

    void shutdown() {
        exec.shutdownNow();
    }
}
