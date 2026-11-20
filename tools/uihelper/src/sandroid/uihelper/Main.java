package sandroid.uihelper;

import android.app.UiAutomation;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.Process;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.CRC32;

/**
 * Sandroid on-device UI helper.
 *
 * <p>Run with {@code CLASSPATH=/data/local/tmp/sandroid-uihelper.jar app_process /
 * sandroid.uihelper.Main [mode=full|invisible] [key=value ...]} over one persistent
 * {@code adb shell}.
 * Line protocol: commands on stdin, one JSON object per line on stdout, each with
 * a {@code "type"}. Replies echo the request {@code id}. All times are device
 * CLOCK_MONOTONIC milliseconds (same clock as {@code getevent -t} and a11y
 * EventTime). Exits (releasing the single UiAutomation connection) on stdin EOF.
 *
 * <p>{@code mode=full} (default) connects as an a11y client (events, node queries,
 * screenshots). {@code mode=invisible} connects without the a11y subsystem: only
 * {@code shot}, {@code ping}, {@code stats}, {@code config} and {@code touch_watch}
 * work; {@code node_at}, {@code dump}, {@code windows} and {@code clear_cache}
 * reply {@code {"type":"error","error":"mode"}}.
 */
public final class Main {
    static final String VERSION = "1.2.0";
    static final int PROTOCOL = 2;

    static double monoMs() {
        return System.nanoTime() / 1e6;
    }

    static double r1(double v) {
        return Math.round(v * 10) / 10.0;
    }

    // ================================================================ output

    /** Single writer thread; events are dropped (and counted) when the host lags. */
    static final class Out implements Runnable {
        private final LinkedBlockingDeque<String> q = new LinkedBlockingDeque<>();
        private final AtomicInteger pending = new AtomicInteger();
        private final AtomicLong droppedUnreported = new AtomicLong();
        final AtomicLong dropped = new AtomicLong();
        final AtomicLong lines = new AtomicLong();
        volatile int eventCap = 4096;
        private final OutputStream os;

        Out(OutputStream os) {
            this.os = os;
        }

        void reply(JSONObject o) {
            pending.incrementAndGet();
            q.add(o.toString());
        }

        boolean event(JSONObject o) {
            if (pending.get() >= eventCap) {
                dropped.incrementAndGet();
                droppedUnreported.incrementAndGet();
                return false;
            }
            long d = droppedUnreported.getAndSet(0);
            if (d > 0) {
                try {
                    o.put("dropped_before", d);
                } catch (JSONException ignored) {
                    // cannot happen for a long
                }
            }
            pending.incrementAndGet();
            q.add(o.toString());
            return true;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    String s = q.take();
                    os.write(s.getBytes(StandardCharsets.UTF_8));
                    os.write('\n');
                    pending.decrementAndGet();
                    lines.incrementAndGet();
                    if (q.isEmpty()) {
                        os.flush();
                    }
                }
            } catch (InterruptedException | IOException e) {
                // host went away or shutdown
            }
        }

        void drain(long timeoutMs) {
            long end = System.currentTimeMillis() + timeoutMs;
            while (pending.get() > 0 && System.currentTimeMillis() < end) {
                try {
                    Thread.sleep(5);
                } catch (InterruptedException e) {
                    return;
                }
            }
            try {
                os.flush();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    // =============================================================== display

    /** Logical display size + rotation, via DisplayManagerGlobal (hidden). */
    static final class Display {
        volatile int width;
        volatile int height;
        volatile int rotation;
        volatile double at = -1;
        volatile String error;

        Display refreshIfStale(double maxAgeMs) {
            if (at < 0 || monoMs() - at > maxAgeMs) {
                refresh();
            }
            return this;
        }

        synchronized void refresh() {
            try {
                Class<?> dmg = Class.forName("android.hardware.display.DisplayManagerGlobal");
                Object g = dmg.getMethod("getInstance").invoke(null);
                Object info = dmg.getMethod("getDisplayInfo", int.class).invoke(g, 0);
                width = info.getClass().getField("logicalWidth").getInt(info);
                height = info.getClass().getField("logicalHeight").getInt(info);
                rotation = info.getClass().getField("rotation").getInt(info);
                at = monoMs();
            } catch (Throwable t) {
                error = t.toString();
            }
        }

        JSONObject json() throws JSONException {
            return new JSONObject().put("w", width).put("h", height).put("rotation", rotation);
        }
    }

    // ================================================================ config

    static final class Config {
        volatile String content = "coalesce"; // off | coalesce | all
        volatile String src = "interactive"; // off | interactive | all
        volatile int coalesceMs = 250;
        volatile int textMax = 2000;
        volatile int labelMax = 300;
        volatile int snapMaxNodes = 6000;
        volatile int snapMaxMs = 2500;
        volatile int dumpMaxNodes = 50000;
        volatile int dumpMaxMs = 30000;
        volatile boolean events = true;
        volatile boolean visibleOnly = true;
        volatile int maxDepth = 0;
        volatile boolean warm = true; // pre-load a new window's web content
    }

    // ================================================================= state

    private final Config cfg = new Config();
    private final Out out;
    private final Display display = new Display();
    private final Uia uia;
    private final Snapshots snaps;
    private final ScheduledExecutorService evExec = daemonScheduled("uihelper-ev");
    private final ScheduledExecutorService wdExec = daemonScheduled("uihelper-wd");
    private final ThreadPoolExecutor cmdPool = new ThreadPoolExecutor(3, 3, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<Runnable>(64), daemonFactory("uihelper-cmd"));
    private final ThreadPoolExecutor touchPool = new ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS,
            new ArrayBlockingQueue<Runnable>(16), daemonFactory("uihelper-touch-resolve"));
    /** Web warm-up of new windows, off the event and command threads. */
    private final ScheduledExecutorService warmExec = daemonScheduled("uihelper-warm");
    private final java.util.Set<Integer> warmPending = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** windowId -> warm-up attempts (bounded, oldest dropped); MAX_VALUE once warmed. */
    private final LinkedHashMap<Integer, Integer> warmTries = new LinkedHashMap<>();
    private final AtomicLong warms = new AtomicLong();
    private volatile TouchWatch touch;
    private volatile boolean closing;
    private final double startMs = monoMs();
    private final String helperMode;
    private final Object shotLock = new Object();
    private byte[] shotBuf = new byte[0];

    // stats
    private final AtomicLong evIn = new AtomicLong();
    private final AtomicLong evOut = new AtomicLong();
    private final AtomicLong evCoalesced = new AtomicLong();
    private final AtomicLong srcCalls = new AtomicLong();
    private final AtomicLong srcNull = new AtomicLong();
    private volatile double srcMsTotal;
    private volatile double srcMsMax;
    private final AtomicLong nullRoots = new AtomicLong();
    private final AtomicLong reconnects = new AtomicLong();
    private final AtomicLong shots = new AtomicLong();
    private volatile double connectMs = -1;
    private volatile double backoffUntil;
    private volatile int backoffMs = 1000;

    // coalescing (evExec thread only)
    private static final class Pending {
        JSONObject first;
        int n;
        int cct;
        double lastT;
        JSONObject last;
    }

    private final LinkedHashMap<String, Pending> coalesce = new LinkedHashMap<>();

    private Main(String[] args) throws Exception {
        PrintStream realOut = new PrintStream(new FileOutputStream(FileDescriptor.out));
        out = new Out(new BufferedOutputStream(realOut, 1 << 16));
        // Framework code must never write into the protocol stream.
        System.setOut(System.err);
        Map<String, String> kv = new HashMap<>();
        for (String a : args) {
            int eq = a.indexOf('=');
            if (eq > 0) {
                kv.put(a.substring(0, eq), a.substring(eq + 1));
            }
        }
        boolean nonImportant = !"0".equals(kv.remove("nonimportant"));
        String m = kv.containsKey("mode") ? kv.remove("mode") : "full";
        helperMode = oneOf(m, "full", "invisible");
        int flags = "invisible".equals(helperMode) ? Uia.FLAG_INVISIBLE : Uia.FLAG_FULL;
        uia = new Uia(this::onEventLooper, nonImportant, flags);
        snaps = new Snapshots(this::captureSnapshot);
        if (!uia.usesA11y()) {
            cfg.events = false; // no listener is registered anyway
            snaps.enabled = false; // snapshots need window/node queries
        }
        applyConfig(kv);
    }

    private static java.util.concurrent.ThreadFactory daemonFactory(final String name) {
        final AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, name + "-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    private static ScheduledExecutorService daemonScheduled(String name) {
        return Executors.newSingleThreadScheduledExecutor(daemonFactory(name));
    }

    /**
     * AccessibilityInteractionClient builds a Handler on the main looper, so the
     * process needs one. Run it on its own thread so stdin can block on main.
     */
    private static void startMainLooper() throws InterruptedException {
        final java.util.concurrent.CountDownLatch ready = new java.util.concurrent.CountDownLatch(1);
        Thread t = new Thread(() -> {
            android.os.Looper.prepareMainLooper();
            ready.countDown();
            android.os.Looper.loop();
        }, "uihelper-main-looper");
        t.setDaemon(true);
        t.start();
        ready.await();
    }

    public static void main(String[] args) {
        try {
            startMainLooper();
            new Main(args).run();
        } catch (Throwable t) {
            System.err.println("uihelper fatal: " + t);
            t.printStackTrace();
            System.exit(2);
        }
    }

    private void run() throws Exception {
        Thread w = new Thread(out, "uihelper-out");
        w.setDaemon(true);
        w.start();
        display.refresh();
        out.reply(new JSONObject()
                .put("type", "hello")
                .put("version", VERSION)
                .put("protocol", PROTOCOL)
                .put("sdk", Build.VERSION.SDK_INT)
                .put("pid", Process.myPid())
                .put("uid", Process.myUid())
                .put("mode", helperMode)
                .put("flags", uia.flags)
                .put("t_mono_ms", r1(monoMs()))
                .put("display", display.json()));
        Runtime.getRuntime().addShutdownHook(new Thread(uia::disconnect, "uihelper-shutdown"));
        tryConnect("start");
        wdExec.scheduleWithFixedDelay(this::watchdog, 2000, 2000, TimeUnit.MILLISECONDS);

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.equals("quit") || line.equals("exit")) {
                break;
            }
            handleLine(line);
        }
        shutdown();
    }

    private void shutdown() {
        closing = true;
        wdExec.shutdownNow();
        warmExec.shutdownNow();
        TouchWatch t = touch;
        if (t != null) {
            t.stop();
        }
        snaps.shutdown();
        uia.disconnect();
        try {
            out.reply(new JSONObject().put("type", "bye").put("t_mono_ms", r1(monoMs())));
        } catch (JSONException ignored) {
            // unreachable
        }
        out.drain(1000);
        System.exit(0);
    }

    // ============================================================ connection

    private void tryConnect(String why) {
        double t0 = monoMs();
        try {
            uia.connect();
            connectMs = monoMs() - t0;
            backoffMs = 1000;
            status("connected", why, null);
            snaps.kick();
        } catch (Throwable e) {
            String msg = String.valueOf(e.getMessage());
            boolean busy = msg.contains("already registered") || msg.contains("already connected");
            backoffUntil = monoMs() + backoffMs;
            backoffMs = Math.min(backoffMs * 2, 10000);
            status(busy ? "busy" : "error", why, msg);
        }
    }

    private void status(String state, String why, String detail) {
        try {
            JSONObject o = new JSONObject()
                    .put("type", "status")
                    .put("state", state)
                    .put("reason", why)
                    .put("t_mono_ms", r1(monoMs()))
                    .put("mode", helperMode)
                    .put("include_not_important", uia.includeNotImportant());
            if (connectMs >= 0 && "connected".equals(state)) {
                o.put("connect_ms", r1(connectMs));
            }
            o.putOpt("detail", detail);
            out.reply(o);
        } catch (JSONException ignored) {
            // unreachable
        }
    }

    private void watchdog() {
        try {
            if (closing || uia.healthy()) {
                return;
            }
            if (monoMs() < backoffUntil) {
                return;
            }
            if (uia.isConnected()) {
                status("lost", "watchdog", null);
            }
            reconnects.incrementAndGet();
            tryConnect("reconnect");
        } catch (Throwable t) {
            // keep the watchdog alive no matter what
        }
    }

    // ================================================================ events

    private void onEventLooper(final AccessibilityEvent e) {
        final double recv = monoMs();
        evIn.incrementAndGet();
        try {
            evExec.execute(() -> handleEvent(e, recv));
        } catch (RejectedExecutionException ignored) {
            // shutting down
        }
    }

    private static boolean changesUi(int type) {
        switch (type) {
            case AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED:
            case AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUS_CLEARED:
            case AccessibilityEvent.TYPE_VIEW_HOVER_ENTER:
            case AccessibilityEvent.TYPE_VIEW_HOVER_EXIT:
            case AccessibilityEvent.TYPE_ANNOUNCEMENT:
            case AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED:
            case AccessibilityEvent.TYPE_TOUCH_INTERACTION_START:
            case AccessibilityEvent.TYPE_TOUCH_INTERACTION_END:
            case AccessibilityEvent.TYPE_TOUCH_EXPLORATION_GESTURE_START:
            case AccessibilityEvent.TYPE_TOUCH_EXPLORATION_GESTURE_END:
            case AccessibilityEvent.TYPE_GESTURE_DETECTION_START:
            case AccessibilityEvent.TYPE_GESTURE_DETECTION_END:
                return false;
            default:
                return true;
        }
    }

    private static boolean noisy(int type) {
        return type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED
                || type == AccessibilityEvent.TYPE_VIEW_SCROLLED
                || type == AccessibilityEvent.TYPE_WINDOWS_CHANGED;
    }

    private static boolean interactive(int type) {
        switch (type) {
            case AccessibilityEvent.TYPE_VIEW_CLICKED:
            case AccessibilityEvent.TYPE_VIEW_LONG_CLICKED:
            case AccessibilityEvent.TYPE_VIEW_CONTEXT_CLICKED:
            case AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED:
                // getSource() is a blocking IPC into the app (2 ms typical, 200-300 ms while
                // it navigates) and runs on the event thread, so keep this set small.
                return true;
            default:
                return false;
        }
    }

    static String evName(int type) {
        String s = AccessibilityEvent.eventTypeToString(type);
        if (s.startsWith("TYPE_VIEW_")) {
            return s.substring(10);
        }
        return s.startsWith("TYPE_") ? s.substring(5) : s;
    }

    /** evExec thread. */
    private void handleEvent(AccessibilityEvent e, double recv) {
        try {
            int type = e.getEventType();
            if (changesUi(type)) {
                snaps.onChange(e.getEventTime());
            }
            if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                scheduleWarm(e.getWindowId());
            }
            if (!cfg.events) {
                return;
            }
            String mode = cfg.content;
            if (noisy(type) && !"all".equals(mode)) {
                if ("off".equals(mode) && type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
                    return;
                }
                addCoalesced(e, recv);
                return;
            }
            flushCoalesced(); // keep stream order for everything older
            String src = cfg.src;
            boolean wantSrc = "all".equals(src) || ("interactive".equals(src) && interactive(type));
            if (out.event(eventJson(e, recv, wantSrc))) {
                evOut.incrementAndGet();
            }
        } catch (Throwable t) {
            errorLine(null, "event", t);
        }
    }

    private void addCoalesced(AccessibilityEvent e, double recv) throws JSONException {
        String key = e.getEventType() + ":" + e.getWindowId() + ":" + e.getPackageName();
        Pending p = coalesce.get(key);
        if (p == null) {
            p = new Pending();
            p.first = eventJson(e, recv, false);
            coalesce.put(key, p);
            final String k = key;
            evExec.schedule(() -> flushOne(k), cfg.coalesceMs, TimeUnit.MILLISECONDS);
        } else {
            evCoalesced.incrementAndGet();
            if (e.getEventType() == AccessibilityEvent.TYPE_VIEW_SCROLLED) {
                p.last = eventJson(e, recv, false);
            }
        }
        p.n++;
        p.cct |= e.getContentChangeTypes();
        p.lastT = e.getEventTime();
    }

    private void flushOne(String key) {
        Pending p = coalesce.remove(key);
        if (p != null) {
            emitPending(p);
        }
    }

    private void flushCoalesced() {
        if (coalesce.isEmpty()) {
            return;
        }
        for (Iterator<Pending> it = coalesce.values().iterator(); it.hasNext(); ) {
            emitPending(it.next());
            it.remove();
        }
    }

    private void emitPending(Pending p) {
        try {
            JSONObject o = p.first;
            if (p.n > 1) {
                o.put("n", p.n);
                o.put("t_last_mono_ms", p.lastT);
                if (p.cct != 0) {
                    o.put("cct", p.cct);
                }
                if (p.last != null) {
                    for (String k : new String[] {"scroll_x", "scroll_y", "dx", "dy", "from", "to"}) {
                        if (p.last.has(k)) {
                            o.put(k, p.last.get(k));
                        }
                    }
                }
            }
            if (out.event(o)) {
                evOut.incrementAndGet();
            }
        } catch (JSONException ignored) {
            // unreachable
        }
    }

    private JSONObject eventJson(AccessibilityEvent e, double recv, boolean withSrc) throws JSONException {
        int type = e.getEventType();
        int tm = cfg.textMax;
        JSONObject o = new JSONObject();
        o.put("type", "ev");
        o.put("ev", evName(type));
        o.put("t_mono_ms", e.getEventTime());
        o.put("t_recv_ms", r1(recv));
        o.putOpt("pkg", Tree.str(e.getPackageName(), 200));
        o.putOpt("cls", Tree.str(e.getClassName(), 200));
        List<CharSequence> texts = e.getText();
        if (texts != null && !texts.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (CharSequence cs : texts) {
                if (cs == null) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append(" / ");
                }
                sb.append(cs);
            }
            o.putOpt("text", Tree.str(sb, tm));
        }
        o.putOpt("desc", Tree.str(e.getContentDescription(), tm));
        if (e.isPassword()) {
            o.put("password", true);
        }
        if (Build.VERSION.SDK_INT >= 34 && e.isAccessibilityDataSensitive()) {
            o.put("data_sensitive", true);
        }
        o.put("window_id", e.getWindowId());
        if (e.isChecked()) {
            o.put("checked", true);
        }
        if (!e.isEnabled()) {
            o.put("enabled", false);
        }
        if (e.getAction() != 0) {
            o.put("action", e.getAction());
        }
        switch (type) {
            case AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED:
                o.putOpt("before", Tree.str(e.getBeforeText(), tm));
                o.put("from", e.getFromIndex());
                o.put("added", e.getAddedCount());
                o.put("removed", e.getRemovedCount());
                break;
            case AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED:
                o.put("from", e.getFromIndex());
                o.put("to", e.getToIndex());
                o.put("item_count", e.getItemCount());
                break;
            case AccessibilityEvent.TYPE_VIEW_SCROLLED:
                o.put("scroll_x", e.getScrollX());
                o.put("scroll_y", e.getScrollY());
                if (Build.VERSION.SDK_INT >= 28) {
                    o.put("dx", e.getScrollDeltaX());
                    o.put("dy", e.getScrollDeltaY());
                }
                o.put("from", e.getFromIndex());
                o.put("to", e.getToIndex());
                o.put("item_count", e.getItemCount());
                break;
            case AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED:
            case AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED:
                if (e.getContentChangeTypes() != 0) {
                    o.put("cct", e.getContentChangeTypes());
                }
                break;
            case AccessibilityEvent.TYPE_WINDOWS_CHANGED:
                if (Build.VERSION.SDK_INT >= 28) {
                    o.put("wct", e.getWindowChanges());
                }
                break;
            default:
                break;
        }
        if (withSrc) {
            double t0 = monoMs();
            AccessibilityNodeInfo n = null;
            try {
                n = e.getSource();
            } catch (Throwable ignored) {
                // stale / disconnected
            }
            srcCalls.incrementAndGet();
            if (n != null) {
                Tree.SNode s = Tree.copy(n, e.getWindowId(), 0, 0, tm);
                s.info = n;
                JSONObject sj = Tree.nodeJson(s);
                if (type == AccessibilityEvent.TYPE_VIEW_CLICKED
                        || type == AccessibilityEvent.TYPE_VIEW_LONG_CLICKED) {
                    sj.putOpt("label", Tree.label(s, tm, 40, cfg.labelMax));
                }
                o.put("src", sj);
            } else {
                srcNull.incrementAndGet();
            }
            double dt = monoMs() - t0;
            srcMsTotal += dt;
            srcMsMax = Math.max(srcMsMax, dt);
            o.put("src_ms", r1(dt));
        }
        return o;
    }

    // ============================================================== commands

    private static final class Cmd {
        String name;
        String id;
        final List<String> pos = new ArrayList<>();
        final Map<String, String> kv = new LinkedHashMap<>();
    }

    private static Cmd parse(String line) {
        Cmd c = new Cmd();
        String[] tok = line.split("\\s+");
        c.name = tok[0];
        for (int i = 1; i < tok.length; i++) {
            String t = tok[i];
            int eq = t.indexOf('=');
            if (eq > 0) {
                String k = t.substring(0, eq);
                String v = t.substring(eq + 1);
                if (k.equals("id")) {
                    c.id = v;
                } else {
                    c.kv.put(k, v);
                }
            } else {
                c.pos.add(t);
            }
        }
        return c;
    }

    private static final String[] MODES = {"live", "cached", "both"};

    private static boolean isMode(String s) {
        for (String m : MODES) {
            if (m.equals(s)) {
                return true;
            }
        }
        return false;
    }

    /** Last bare token that is not a known keyword becomes the request id. */
    private static void takeId(Cmd c, int fixedArgs) {
        if (c.id == null && c.pos.size() > fixedArgs) {
            String last = c.pos.get(c.pos.size() - 1);
            if (!isMode(last)) {
                c.id = last;
                c.pos.remove(c.pos.size() - 1);
            }
        }
    }

    private void handleLine(String line) {
        final Cmd c = parse(line);
        try {
            if (A11Y_ONLY.contains(c.name) && !uia.usesA11y()) {
                takeId(c, 0);
                modeError(c);
                return;
            }
            switch (c.name) {
                case "ping":
                    takeId(c, 0);
                    ping(c);
                    break;
                case "node_at":
                    takeId(c, 2);
                    if (c.pos.size() < 2) {
                        throw new IllegalArgumentException("usage: node_at <x> <y> [live|cached|both] [t=<mono_ms>] [id]");
                    }
                    final int x = Integer.parseInt(c.pos.get(0));
                    final int y = Integer.parseInt(c.pos.get(1));
                    final String mode = c.pos.size() > 2 ? c.pos.get(2) : "live";
                    final double reqMs = monoMs();
                    if ("cached".equals(mode)) {
                        nodeAt(c, x, y, mode, reqMs); // no IPC: answer inline
                    } else {
                        submit(c, () -> nodeAt(c, x, y, mode, reqMs));
                    }
                    break;
                case "dump":
                    takeId(c, 0);
                    submit(c, () -> dump(c));
                    break;
                case "windows":
                    takeId(c, 0);
                    submit(c, () -> windows(c));
                    break;
                case "focus":
                    takeId(c, 0);
                    submit(c, () -> focus(c));
                    break;
                case "config":
                    takeId(c, 0);
                    applyConfig(c.kv);
                    out.reply(configJson().put("type", "config").putOpt("id", c.id));
                    break;
                case "stats":
                    takeId(c, 0);
                    out.reply(statsJson().put("type", "stats").putOpt("id", c.id));
                    break;
                case "touch_watch":
                    touchWatch(c);
                    break;
                case "shot":
                    takeId(c, 0);
                    submit(c, () -> shot(c));
                    break;
                case "clear_cache":
                    takeId(c, 0);
                    boolean ok = uia.get().clearCache();
                    out.reply(new JSONObject().put("type", "ok").putOpt("id", c.id).put("cleared", ok));
                    break;
                case "_drop":
                    takeId(c, 0);
                    uia.simulateLoss();
                    out.reply(new JSONObject().put("type", "ok").putOpt("id", c.id));
                    break;
                default:
                    takeId(c, 0);
                    throw new IllegalArgumentException("unknown command: " + c.name);
            }
        } catch (Throwable t) {
            errorLine(c.id, c.name, t);
        }
    }

    /** Commands that need the a11y connection (unavailable in invisible mode). */
    private static final java.util.Set<String> A11Y_ONLY = new java.util.HashSet<>(
            java.util.Arrays.asList("node_at", "dump", "windows", "clear_cache", "focus"));

    private void modeError(Cmd c) throws JSONException {
        out.reply(new JSONObject()
                .put("type", "error")
                .putOpt("id", c.id)
                .put("cmd", c.name)
                .put("error", "mode")
                .put("mode", helperMode)
                .put("t_mono_ms", r1(monoMs())));
    }

    private interface Job {
        void run() throws Exception;
    }

    private void submit(final Cmd c, final Job job) {
        try {
            cmdPool.execute(() -> {
                try {
                    job.run();
                } catch (Throwable t) {
                    errorLine(c.id, c.name, t);
                }
            });
        } catch (RejectedExecutionException e) {
            errorLine(c.id, c.name, new IllegalStateException("overloaded: too many queued commands"));
        }
    }

    private void errorLine(String id, String cmd, Throwable t) {
        try {
            JSONObject o = new JSONObject()
                    .put("type", "error")
                    .putOpt("id", id)
                    .putOpt("cmd", cmd)
                    .put("error", t.getClass().getSimpleName() + ": " + t.getMessage())
                    .put("t_mono_ms", r1(monoMs()));
            if (t instanceof IllegalStateException && String.valueOf(t.getMessage()).contains("not connected")) {
                o.put("code", "not_connected");
            }
            out.reply(o);
        } catch (JSONException ignored) {
            // unreachable
        }
    }

    private JSONObject base(String type, Cmd c, double reqMs) throws JSONException {
        return new JSONObject().put("type", type).putOpt("id", c.id).put("t_req_ms", r1(reqMs));
    }

    private void finish(JSONObject o, double reqMs) throws JSONException {
        double now = monoMs();
        o.put("t_mono_ms", r1(now));
        o.put("compute_ms", r1(now - reqMs));
        out.reply(o);
    }

    private void ping(Cmd c) throws JSONException {
        double now = monoMs();
        out.reply(new JSONObject()
                .put("type", "pong")
                .putOpt("id", c.id)
                .put("t_mono_ms", r1(now))
                .put("connected", uia.isConnected())
                .put("uptime_ms", r1(now - startMs))
                .put("mode", helperMode)
                .put("version", VERSION));
    }

    private void applyConfig(Map<String, String> kv) {
        for (Map.Entry<String, String> en : kv.entrySet()) {
            String k = en.getKey();
            String v = en.getValue();
            switch (k) {
                case "nonimportant":
                    uia.setIncludeNotImportant(!"0".equals(v));
                    snaps.clear();
                    snaps.kick();
                    break;
                case "content":
                    cfg.content = oneOf(v, "off", "coalesce", "all");
                    break;
                case "src":
                    cfg.src = oneOf(v, "off", "interactive", "all");
                    break;
                case "events":
                    cfg.events = uia.usesA11y() && !"0".equals(v);
                    break;
                case "coalesce_ms":
                    cfg.coalesceMs = Integer.parseInt(v);
                    break;
                case "text_max":
                    cfg.textMax = Integer.parseInt(v);
                    break;
                case "cache":
                    snaps.enabled = uia.usesA11y() && !"0".equals(v);
                    if (snaps.enabled) {
                        snaps.kick();
                    } else {
                        snaps.clear();
                    }
                    break;
                case "quiet_ms":
                    snaps.quietMs = Double.parseDouble(v);
                    break;
                case "max_stale_ms":
                    snaps.maxStaleMs = Double.parseDouble(v);
                    break;
                case "min_interval_ms":
                    snaps.minIntervalMs = Double.parseDouble(v);
                    break;
                case "ring":
                    snaps.ringSize = Math.max(1, Math.min(16, Integer.parseInt(v)));
                    break;
                case "snap_max_nodes":
                    cfg.snapMaxNodes = Integer.parseInt(v);
                    break;
                case "snap_max_ms":
                    cfg.snapMaxMs = Integer.parseInt(v);
                    break;
                case "visible_only":
                    cfg.visibleOnly = !"0".equals(v);
                    break;
                case "max_depth":
                    cfg.maxDepth = Integer.parseInt(v);
                    break;
                case "event_cap":
                    out.eventCap = Integer.parseInt(v);
                    break;
                case "warm":
                    cfg.warm = !"0".equals(v);
                    break;
                default:
                    throw new IllegalArgumentException("unknown config key: " + k);
            }
        }
    }

    private static String oneOf(String v, String... allowed) {
        for (String a : allowed) {
            if (a.equals(v)) {
                return v;
            }
        }
        throw new IllegalArgumentException("value must be one of " + java.util.Arrays.toString(allowed) + ": " + v);
    }

    private JSONObject configJson() throws JSONException {
        return new JSONObject()
                .put("nonimportant", uia.includeNotImportant() ? 1 : 0)
                .put("content", cfg.content)
                .put("src", cfg.src)
                .put("events", cfg.events ? 1 : 0)
                .put("coalesce_ms", cfg.coalesceMs)
                .put("text_max", cfg.textMax)
                .put("cache", snaps.enabled ? 1 : 0)
                .put("quiet_ms", snaps.quietMs)
                .put("max_stale_ms", snaps.maxStaleMs)
                .put("min_interval_ms", snaps.minIntervalMs)
                .put("ring", snaps.ringSize)
                .put("snap_max_nodes", cfg.snapMaxNodes)
                .put("snap_max_ms", cfg.snapMaxMs)
                .put("visible_only", cfg.visibleOnly ? 1 : 0)
                .put("max_depth", cfg.maxDepth)
                .put("event_cap", out.eventCap)
                .put("warm", cfg.warm ? 1 : 0);
    }

    private JSONObject statsJson() throws JSONException {
        Runtime rt = Runtime.getRuntime();
        long sc = srcCalls.get();
        Snapshots.Snap last = snaps.latest();
        JSONObject o = new JSONObject()
                .put("t_mono_ms", r1(monoMs()))
                .put("connected", uia.isConnected())
                .put("mode", helperMode)
                .put("shots", shots.get())
                .put("warms", warms.get())
                .put("connects", uia.connects)
                .put("reconnects", reconnects.get())
                .put("ev_in", evIn.get())
                .put("ev_out", evOut.get())
                .put("ev_coalesced", evCoalesced.get())
                .put("ev_dropped", out.dropped.get())
                .put("lines_out", out.lines.get())
                .put("src_calls", sc)
                .put("src_null", srcNull.get())
                .put("src_ms_avg", sc == 0 ? 0 : r1(srcMsTotal / sc))
                .put("src_ms_max", r1(srcMsMax))
                .put("null_roots", nullRoots.get())
                .put("snapshots", snaps.taken)
                .put("snapshot_failures", snaps.failures)
                .put("snapshot_ms_avg", snaps.taken == 0 ? 0 : r1(snaps.tookTotalMs / snaps.taken))
                .put("snapshot_ms_last", r1(snaps.lastTookMs()))
                .put("snapshot_ring", snaps.size())
                .put("snapshot_nodes_held", snaps.nodesHeld())
                .put("heap_used_kb", (rt.totalMemory() - rt.freeMemory()) / 1024)
                .put("heap_max_kb", rt.maxMemory() / 1024)
                .put("threads", Thread.activeCount());
        if (last != null) {
            o.put("snapshot_last_nodes", last.nodes).put("snapshot_last_end_ms", r1(last.endMs));
        }
        TouchWatch t = touch;
        if (t != null) {
            o.put("touch_error", t.error == null ? JSONObject.NULL : t.error);
            o.put("touch_realtime_clock", t.realtimeClock == null ? JSONObject.NULL : t.realtimeClock);
        }
        return o;
    }

    // =============================================================== queries

    private Tree.Limits limits(int maxNodes, int maxMs) {
        Tree.Limits l = new Tree.Limits();
        l.maxNodes = maxNodes;
        l.maxMs = maxMs;
        l.textMax = cfg.textMax;
        l.visibleOnly = cfg.visibleOnly;
        l.maxDepth = cfg.maxDepth;
        return l;
    }

    /** Full copy of all interactive windows (top-most first), bounded. */
    private Snapshots.Snap capture(Tree.Limits lim) {
        Snapshots.Snap s = new Snapshots.Snap();
        s.startMs = monoMs();
        UiAutomation u = uia.get();
        List<AccessibilityWindowInfo> ws = Tree.zOrder(u.getWindows());
        int[] budget = {lim.maxNodes};
        long deadline = System.nanoTime() + lim.maxMs * 1_000_000L;
        ArrayList<Tree.SWindow> list = new ArrayList<>();
        for (AccessibilityWindowInfo w : ws) {
            Tree.SWindow sw = Tree.copyWindow(w);
            AccessibilityNodeInfo r = Tree.rootOf(w);
            if (r == null) {
                nullRoots.incrementAndGet();
            } else {
                Tree.SNode root = Tree.copy(r, sw.id, 0, 0, lim.textMax);
                root.info = r;
                budget[0]--;
                sw.truncated = Tree.copyAll(root, lim, budget, deadline);
                sw.root = root;
                s.truncated |= sw.truncated;
            }
            list.add(sw);
        }
        s.windows = list;
        s.nodes = lim.maxNodes - Math.max(0, budget[0]);
        s.endMs = monoMs();
        Display d = display.refreshIfStale(1000);
        s.screenW = d.width;
        s.screenH = d.height;
        s.rotation = d.rotation;
        return s;
    }

    private Snapshots.Snap captureSnapshot() {
        return capture(limits(cfg.snapMaxNodes, cfg.snapMaxMs));
    }

    private JSONObject resolveIn(Tree.SWindow sw, int x, int y) throws JSONException {
        Display d = display.refreshIfStale(1000);
        JSONObject r = new JSONObject();
        r.put("window", Tree.windowJson(sw, d.width, d.height));
        if (sw.root == null) {
            r.put("hit", JSONObject.NULL);
            r.put("reason", "no_root");
            return r;
        }
        int tm = cfg.textMax;
        Tree.SNode h = Tree.hit(sw.root, x, y, tm);
        Tree.SNode t = Tree.target(h);
        // A generic web node (a span in a button): its interactive ancestor.
        Tree.SNode wc = Tree.webControl(h);
        if (wc == null && t != null && t != h) {
            wc = Tree.webControl(t);
        }
        if (wc != null) {
            t = wc;
        }
        r.putOpt("pkg", h.pkg != null ? h.pkg : sw.root.pkg);
        r.put("hit", Tree.nodeJson(h).put("depth", h.depth));
        r.put("path", Tree.path(h));
        // Web content: the element on top at this spot when it is not the
        // hit (an unclickable overlay the hit rule above looks through).
        Tree.SNode top = Tree.topmost(sw.root, x, y, tm);
        if (top != h && top.engine != null) {
            r.put("top", Tree.nodeJson(top).put("depth", top.depth));
            r.put("top_path", Tree.path(top));
        }
        if (t != null) {
            r.put("target", Tree.nodeJson(t).put("depth", t.depth));
        }
        r.putOpt("label", Tree.label(t != null ? t : h, tm, 200, cfg.labelMax));
        if (Tree.bareWeb(h)) {
            r.put("bare_web", true);
        }
        JSONObject doc = webDoc(sw, h);
        if (doc != null) {
            r.put("web_doc", doc);
        }
        return r;
    }

    /**
     * The web document around {@code h}: the top document's title, an inner
     * frame's title, and (Chrome, Firefox) the raw text of the window's
     * address bar ({@code bar}; the host still has a localized suffix).
     */
    private JSONObject webDoc(Tree.SWindow sw, Tree.SNode h) throws JSONException {
        Tree.SNode outer = null;
        Tree.SNode inner = null;
        for (Tree.SNode s = h; s != null; s = s.parent) {
            if (Tree.webDocument(s)) {
                if (inner == null) {
                    inner = s;
                }
                outer = s;
            }
        }
        if (outer == null) {
            return null;
        }
        JSONObject o = new JSONObject().putOpt("title", Tree.webTitle(outer));
        if (inner != outer) {
            o.putOpt("frame", Tree.webTitle(inner));
        }
        try {
            o.putOpt("bar", addressBar(sw));
        } catch (Throwable ignored) {
            // the toolbar went away meanwhile
        }
        return o;
    }

    private static boolean chromePkg(String pkg) {
        return pkg.equals("com.android.chrome") || pkg.startsWith("com.chrome.")
                || pkg.startsWith("org.chromium.");
    }

    /** Text of a browser's address bar node, or null (hint, other node). */
    private static String barText(String rid, CharSequence text, CharSequence desc, boolean hint) {
        if (rid == null) {
            return null;
        }
        if (rid.endsWith(":id/url_bar") || rid.endsWith(":id/mozac_browser_toolbar_url_view")) {
            return hint ? null : Tree.str(text, 300);
        }
        if (rid.equals("ADDRESSBAR_URL_BOX")) {
            return Tree.str(desc != null ? desc : text, 300);
        }
        return null;
    }

    /**
     * The address bar text of a Chrome / Firefox window. A snapshot has the
     * whole tree in memory; a live query asks the toolbar only (Chrome: one
     * view-id lookup; Firefox: the Compose toolbar's small subtree).
     */
    private String addressBar(Tree.SWindow sw) {
        Tree.SNode root = sw.root;
        String pkg = root == null ? null : root.pkg;
        if (pkg == null || !(chromePkg(pkg) || pkg.startsWith("org.mozilla."))) {
            return null;
        }
        if (root.info == null) { // snapshot
            ArrayList<Tree.SNode> stack = new ArrayList<>();
            stack.add(root);
            while (!stack.isEmpty()) {
                Tree.SNode s = stack.remove(stack.size() - 1);
                String b = barText(s.rid, s.text, s.desc, s.showingHint);
                if (b != null) {
                    return b;
                }
                if (s.kids != null) {
                    stack.addAll(Arrays.asList(s.kids));
                }
            }
            return null;
        }
        String[] ids = chromePkg(pkg)
                ? new String[] {pkg + ":id/url_bar"}
                : new String[] {pkg + ":id/composable_toolbar", pkg + ":id/mozac_browser_toolbar_url_view"};
        for (String id : ids) {
            List<AccessibilityNodeInfo> found = root.info.findAccessibilityNodeInfosByViewId(id);
            if (found == null || found.isEmpty()) {
                continue;
            }
            ArrayList<AccessibilityNodeInfo> q = new ArrayList<>(found.subList(0, 1));
            long end = System.nanoTime() + 60_000_000L;
            for (int i = 0; i < q.size() && i < 80 && System.nanoTime() < end; i++) {
                AccessibilityNodeInfo n = q.get(i);
                boolean hint = Build.VERSION.SDK_INT >= 26 && n.isShowingHintText();
                String b = barText(Tree.str(n.getViewIdResourceName(), 300), n.getText(),
                        n.getContentDescription(), hint);
                if (b != null) {
                    return b;
                }
                for (int k = 0; k < n.getChildCount(); k++) {
                    AccessibilityNodeInfo ch = Build.VERSION.SDK_INT >= 33
                            ? n.getChild(k, AccessibilityNodeInfo.FLAG_PREFETCH_DESCENDANTS_HYBRID)
                            : n.getChild(k);
                    if (ch != null) {
                        q.add(ch);
                    }
                }
            }
        }
        return null;
    }

    /**
     * Live hit test. When it ends on a bare web container (nothing loaded
     * under the finger yet: Gecko builds its tree on first access), it is
     * asked once more after {@link #WEB_RETRY_MS}.
     */
    private JSONObject nodeAtLive(int x, int y) throws JSONException {
        double t0 = monoMs();
        JSONObject r = nodeAtLiveOnce(x, y);
        if (r.optBoolean("bare_web")) {
            try {
                Thread.sleep(WEB_RETRY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return r;
            }
            r = nodeAtLiveOnce(x, y);
            r.put("web_retry", true).put("t_start_ms", r1(t0)).put("ms", r1(monoMs() - t0));
        }
        return r;
    }

    static final long WEB_RETRY_MS = 200;

    private JSONObject nodeAtLiveOnce(int x, int y) throws JSONException {
        double t0 = monoMs();
        UiAutomation u = uia.get();
        JSONObject r = null;
        int attempts = 0;
        while (r == null) {
            attempts++;
            Tree.SWindow hitWin = null;
            for (AccessibilityWindowInfo w : Tree.zOrder(u.getWindows())) {
                Tree.SWindow sw = Tree.copyWindow(w);
                if (!sw.contains(x, y)) {
                    continue;
                }
                hitWin = sw;
                AccessibilityNodeInfo root = Tree.rootOf(w);
                if (root != null) {
                    Tree.SNode sr = Tree.copy(root, sw.id, 0, 0, cfg.textMax);
                    sr.info = root;
                    sw.root = sr;
                } else {
                    nullRoots.incrementAndGet();
                }
                break;
            }
            if (hitWin == null) {
                r = new JSONObject().put("hit", JSONObject.NULL).put("reason", "no_window");
            } else if (hitWin.root == null && attempts < 3) {
                try {
                    Thread.sleep(25); // window in transition: its root appears shortly
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            } else {
                r = resolveIn(hitWin, x, y);
            }
        }
        double t1 = monoMs();
        r.put("t_start_ms", r1(t0)).put("t_end_ms", r1(t1)).put("ms", r1(t1 - t0));
        if (attempts > 1) {
            r.put("attempts", attempts);
        }
        return r;
    }

    private JSONObject nodeAtCached(int x, int y, double atMs) throws JSONException {
        double t0 = monoMs();
        Snapshots.Snap s = snaps.at(atMs);
        JSONObject r = null;
        if (s == null) {
            r = new JSONObject().put("hit", JSONObject.NULL).put("reason", "no_snapshot");
        } else {
            for (Tree.SWindow sw : s.windows) {
                if (sw.contains(x, y)) {
                    r = resolveIn(sw, x, y);
                    break;
                }
            }
            if (r == null) {
                r = new JSONObject().put("hit", JSONObject.NULL).put("reason", "no_window");
            }
            double[] ch = snaps.changesBetween(s.startMs, atMs);
            JSONObject sj = new JSONObject()
                    .put("seq", s.seq)
                    .put("start_ms", r1(s.startMs))
                    .put("end_ms", r1(s.endMs))
                    .put("age_ms", r1(atMs - s.endMs))
                    .put("nodes", s.nodes)
                    .put("changes_since_start", (int) ch[0]);
            if (ch[1] >= 0) {
                sj.put("first_change_ms", ch[1]);
            }
            if (s.changedDuring) {
                sj.put("changed_during", true);
            }
            if (s.truncated) {
                sj.put("truncated", true);
            }
            r.put("snapshot", sj);
            r.put("at_ms", r1(atMs));
        }
        r.put("ms", r1(monoMs() - t0));
        return r;
    }

    private void nodeAt(Cmd c, int x, int y, String mode, double reqMs) throws JSONException {
        JSONObject o = base("node_at", c, reqMs).put("x", x).put("y", y);
        double at = c.kv.containsKey("t") ? Double.parseDouble(c.kv.get("t")) : reqMs;
        if ("cached".equals(mode) || "both".equals(mode)) {
            o.put("cached", nodeAtCached(x, y, at));
        }
        if ("live".equals(mode) || "both".equals(mode)) {
            o.put("live", nodeAtLive(x, y));
        }
        finish(o, reqMs);
    }

    private void dump(Cmd c) throws JSONException {
        double reqMs = monoMs();
        Snapshots.Snap s;
        boolean cached = c.pos.contains("cached");
        if (cached) {
            s = snaps.latest();
            if (s == null) {
                throw new IllegalStateException("no snapshot yet");
            }
        } else {
            int maxNodes = c.kv.containsKey("max_nodes") ? Integer.parseInt(c.kv.get("max_nodes")) : cfg.dumpMaxNodes;
            Tree.Limits lim = limits(maxNodes, cfg.dumpMaxMs);
            if (c.kv.containsKey("visible_only")) {
                lim.visibleOnly = !"0".equals(c.kv.get("visible_only"));
            }
            s = capture(lim);
        }
        JSONObject o = base("dump", c, reqMs);
        JSONArray wa = new JSONArray();
        for (Tree.SWindow sw : s.windows) {
            JSONObject wj = Tree.windowJson(sw, s.screenW, s.screenH);
            if (sw.root != null) {
                wj.put("root", Tree.treeJson(sw.root, null));
            }
            if (sw.truncated) {
                wj.put("truncated", true);
            }
            wa.put(wj);
        }
        o.put("windows", wa);
        o.put("nodes", s.nodes);
        o.put("capture_ms", r1(s.endMs - s.startMs));
        o.put("snapshot_start_ms", r1(s.startMs));
        o.put("cached", cached);
        o.put("include_not_important", uia.includeNotImportant());
        o.put("display", new JSONObject().put("w", s.screenW).put("h", s.screenH).put("rotation", s.rotation));
        if (s.truncated) {
            o.put("truncated", true);
        }
        finish(o, reqMs);
    }

    private void windows(Cmd c) throws JSONException {
        double reqMs = monoMs();
        Display d = display.refreshIfStale(0);
        JSONArray wa = new JSONArray();
        for (AccessibilityWindowInfo w : Tree.zOrder(uia.get().getWindows())) {
            Tree.SWindow sw = Tree.copyWindow(w);
            JSONObject wj = Tree.windowJson(sw, d.width, d.height);
            AccessibilityNodeInfo r = Build.VERSION.SDK_INT >= 33 ? w.getRoot(0) : w.getRoot();
            if (r != null) {
                wj.putOpt("pkg", Tree.str(r.getPackageName(), 200));
            } else {
                wj.put("root", JSONObject.NULL);
            }
            wa.put(wj);
        }
        JSONObject o = base("windows", c, reqMs).put("windows", wa).put("display", d.json());
        finish(o, reqMs);
    }

    // ============================================================ read-back

    /**
     * {@code focus [x=<px> y=<px>] [id]}: the input-focused node, refreshed
     * ({@code input}; its text is the field's value now, also for fields that
     * send no TEXT_CHANGED: Compose, browser address bars). When nothing
     * editable has the input focus and a point is given, the editable node
     * under it (the field that was tapped), refreshed ({@code node}).
     * {@code input} also carries its selection ({@code sel_start},
     * {@code sel_end}; -1 when none is known).
     */
    private void focus(Cmd c) throws JSONException {
        double reqMs = monoMs();
        JSONObject o = base("focus", c, reqMs);
        UiAutomation u = uia.get();
        int tm = cfg.textMax;
        AccessibilityNodeInfo f = null;
        try {
            f = u.findFocus(AccessibilityNodeInfo.FOCUS_INPUT);
        } catch (Throwable ignored) {
            // no focus / window gone
        }
        boolean editable = false;
        if (f != null) {
            f.refresh();
            Tree.SNode s = Tree.copy(f, f.getWindowId(), 0, 0, tm);
            editable = s.editable;
            JSONObject in = Tree.nodeJson(s).put("window_id", s.windowId).putOpt("pkg", s.pkg);
            // The selection (-1 both: none known). Typing replaces a field
            // whose whole text is selected (an address bar on focus).
            in.put("sel_start", f.getTextSelectionStart());
            in.put("sel_end", f.getTextSelectionEnd());
            o.put("input", in);
        }
        if (!editable && c.kv.containsKey("x") && c.kv.containsKey("y")) {
            int x = Integer.parseInt(c.kv.get("x"));
            int y = Integer.parseInt(c.kv.get("y"));
            for (AccessibilityWindowInfo w : Tree.zOrder(u.getWindows())) {
                Tree.SWindow sw = Tree.copyWindow(w);
                if (!sw.contains(x, y)) {
                    continue;
                }
                AccessibilityNodeInfo root = Tree.rootOf(w);
                if (root == null) {
                    break;
                }
                Tree.SNode sr = Tree.copy(root, sw.id, 0, 0, tm);
                sr.info = root;
                for (Tree.SNode s = Tree.hit(sr, x, y, tm); s != null; s = s.parent) {
                    if (s.editable && s.info != null) {
                        s.info.refresh();
                        Tree.SNode fresh = Tree.copy(s.info, sw.id, s.depth, s.index, tm);
                        o.put("node", Tree.nodeJson(fresh).put("window_id", sw.id).putOpt("pkg", fresh.pkg));
                        break;
                    }
                }
                break;
            }
        }
        finish(o, reqMs);
    }

    // ============================================================== warm-up

    /**
     * A window appeared (WINDOW_STATE_CHANGED): warm its web content once,
     * {@link #WARM_DELAY_MS} later on its own thread (never on a tap's path).
     */
    private void scheduleWarm(final int windowId) {
        if (!cfg.warm || !uia.usesA11y() || windowId < 0 || closing) {
            return;
        }
        synchronized (warmTries) {
            Integer tries = warmTries.get(windowId);
            if (tries != null && tries >= WARM_TRIES) {
                return;
            }
        }
        if (!warmPending.add(windowId)) {
            return;
        }
        try {
            warmExec.schedule(() -> {
                warmPending.remove(windowId);
                try {
                    warmWindow(windowId);
                } catch (Throwable ignored) {
                    // not connected / window gone: a later window event retries
                }
            }, WARM_DELAY_MS, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            warmPending.remove(windowId);
        }
    }

    static final long WARM_DELAY_MS = 300;
    /** Attempts per window without a WebView found (it may load later). */
    static final int WARM_TRIES = 3;

    /**
     * Fetch the first two levels under every WebView of an app window, the
     * way a first hit test would: Gecko builds its accessibility tree on
     * first access, so the first tap would see the bare WebView otherwise.
     * Bounded: 400 nodes to find WebViews, 50 children each, 300 ms.
     */
    private void warmWindow(int windowId) {
        UiAutomation u = uia.get();
        for (AccessibilityWindowInfo w : u.getWindows()) {
            if (w.getId() != windowId || w.getType() != AccessibilityWindowInfo.TYPE_APPLICATION) {
                continue;
            }
            AccessibilityNodeInfo root = Tree.rootOf(w);
            if (root == null) {
                return;
            }
            boolean found = false;
            long end = System.nanoTime() + 300_000_000L;
            ArrayList<AccessibilityNodeInfo> q = new ArrayList<>();
            q.add(root);
            for (int i = 0; i < q.size() && i < 400 && System.nanoTime() < end; i++) {
                AccessibilityNodeInfo n = q.get(i);
                CharSequence cls = n.getClassName();
                if (cls != null && "android.webkit.WebView".contentEquals(cls)) {
                    found = true;
                    for (int k = 0; k < Math.min(n.getChildCount(), 50); k++) {
                        AccessibilityNodeInfo ch = n.getChild(k);
                        for (int g = 0; ch != null && g < Math.min(ch.getChildCount(), 50); g++) {
                            ch.getChild(g);
                        }
                    }
                    continue; // the web content itself is not walked here
                }
                for (int k = 0; k < n.getChildCount(); k++) {
                    AccessibilityNodeInfo ch = n.getChild(k);
                    if (ch != null) {
                        q.add(ch);
                    }
                }
            }
            synchronized (warmTries) {
                Integer tries = warmTries.get(windowId);
                warmTries.put(windowId, found ? Integer.MAX_VALUE : (tries == null ? 1 : tries + 1));
                while (warmTries.size() > 64) {
                    warmTries.remove(warmTries.keySet().iterator().next());
                }
            }
            if (found) {
                warms.incrementAndGet();
            }
            return;
        }
    }

    // ================================================================== shot

    /**
     * {@code shot [path=<remote png>] [hash_only=1] [id]}: one
     * {@code UiAutomation.takeScreenshot()} (works in both modes). Replies with the
     * capture instant ({@code t_mono_ms}, CLOCK_MONOTONIC at the call), the size,
     * a crc32 over the ARGB_8888 pixel buffer, and timings. The PNG is written only
     * when {@code path} is given and {@code hash_only} is not set. Shots are
     * serialised: the pixel buffer (about 10 MB) is reused.
     */
    private void shot(Cmd c) throws Exception {
        double reqMs = monoMs();
        String path = c.kv.get("path");
        boolean hashOnly = "1".equals(c.kv.get("hash_only"));
        if (path != null && !path.startsWith("/")) {
            throw new IllegalArgumentException("shot path must be absolute: " + path);
        }
        UiAutomation u = uia.get();
        JSONObject o = base("shot", c, reqMs);
        synchronized (shotLock) {
            double tCap = monoMs();
            Bitmap hw = u.takeScreenshot();
            double tGot = monoMs();
            if (hw == null) {
                throw new IllegalStateException("takeScreenshot returned null");
            }
            Bitmap sw = hw;
            try {
                // takeScreenshot() returns a HARDWARE bitmap on API 31+: no pixel
                // access, so read it back once into a software copy.
                if (Build.VERSION.SDK_INT >= 26 && hw.getConfig() == Bitmap.Config.HARDWARE) {
                    sw = hw.copy(Bitmap.Config.ARGB_8888, false);
                    if (sw == null) {
                        throw new IllegalStateException("hardware bitmap readback failed");
                    }
                }
                int n = sw.getByteCount();
                if (shotBuf.length != n) {
                    shotBuf = new byte[n];
                }
                ByteBuffer bb = ByteBuffer.wrap(shotBuf);
                sw.copyPixelsToBuffer(bb);
                CRC32 crc = new CRC32();
                crc.update(shotBuf, 0, bb.position());
                double tHash = monoMs();
                o.put("t_mono_ms", r1(tCap))
                        .put("w", sw.getWidth())
                        .put("h", sw.getHeight())
                        .put("hash", String.format(java.util.Locale.ROOT, "%08x", crc.getValue()))
                        .put("cap_ms", r1(tGot - tCap))
                        .put("hash_ms", r1(tHash - tGot));
                double pngMs = 0;
                if (path != null && !hashOnly) {
                    try (FileOutputStream fo = new FileOutputStream(path)) {
                        if (!sw.compress(Bitmap.CompressFormat.PNG, 100, fo)) {
                            throw new IOException("PNG encode failed");
                        }
                    }
                    pngMs = monoMs() - tHash;
                    o.put("path", path);
                }
                o.put("png_ms", r1(pngMs));
            } finally {
                if (sw != hw) {
                    sw.recycle();
                }
                hw.recycle();
            }
        }
        shots.incrementAndGet();
        o.put("compute_ms", r1(monoMs() - reqMs));
        out.reply(o);
    }

    // ================================================================= touch

    private void touchWatch(Cmd c) throws JSONException {
        takeId(c, 3);
        TouchWatch old = touch;
        if (old != null) {
            old.stop();
            touch = null;
        }
        if (c.pos.isEmpty() || "off".equals(c.pos.get(0))) {
            out.reply(new JSONObject().put("type", "ok").putOpt("id", c.id).put("touch_watch", false));
            return;
        }
        String path = c.pos.get(0);
        if (!"auto".equals(path) && !path.matches("/dev/input/event\\d+")) {
            throw new IllegalArgumentException("touch_watch needs auto or /dev/input/eventN");
        }
        TouchWatch.Probe pr = TouchWatch.probe("auto".equals(path) ? null : path);
        if (pr == null && "auto".equals(path)) {
            throw new IllegalStateException("no multi-touch input device found");
        }
        if (pr != null) {
            path = pr.path;
        }
        int maxX = c.pos.size() > 1 ? Integer.parseInt(c.pos.get(1)) : 32767;
        int maxY = c.pos.size() > 2 ? Integer.parseInt(c.pos.get(2)) : 32767;
        TouchWatch t = new TouchWatch(path, maxX, maxY, display, new TouchWatch.Sink() {
            @Override
            public void onDown(int slot, double tMs, int x, int y, int rawX, int rawY, boolean uncertain) {
                onTouchDown(slot, tMs, x, y, rawX, rawY, uncertain);
            }

            @Override
            public void onUp(int slot, double tMs, double downMs, int x0, int y0, int x1, int y1, int mv) {
                try {
                    JSONObject o = new JSONObject().put("type", "touch").put("phase", "up")
                            .put("slot", slot).put("t_mono_ms", r1(tMs)).put("t_down_ms", r1(downMs))
                            .put("dur_ms", r1(tMs - downMs))
                            .put("start", new JSONArray().put(x0).put(y0))
                            .put("end", new JSONArray().put(x1).put(y1))
                            .put("max_move_px", mv);
                    out.reply(o);
                } catch (JSONException ignored) {
                    // unreachable
                }
            }
        });
        t.seed(pr);
        touch = t;
        t.start();
        out.reply(new JSONObject().put("type", "ok").putOpt("id", c.id).put("touch_watch", t.path())
                .put("max", new JSONArray().put(t.maxX()).put(t.maxY())).put("probed", pr != null));
    }

    private void onTouchDown(int slot, final double tMs, final int x, final int y, int rawX, int rawY,
            boolean uncertain) {
        final double seen = monoMs();
        try {
            out.reply(new JSONObject().put("type", "touch").put("phase", "down").put("slot", slot)
                    .put("t_mono_ms", r1(tMs)).put("x", x).put("y", y)
                    .put("raw", new JSONArray().put(rawX).put(rawY))
                    .put("seen_delay_ms", r1(seen - tMs))
                    .put("xy_uncertain", uncertain));
        } catch (JSONException ignored) {
            // unreachable
        }
        if (slot != 0 || !uia.usesA11y()) {
            return; // resolve the primary finger only, and only with a11y
        }
        try {
            touchPool.execute(() -> {
                try {
                    JSONObject o = new JSONObject().put("type", "touch_node").put("t_mono_ms", r1(tMs))
                            .put("x", x).put("y", y);
                    o.put("cached", nodeAtCached(x, y, tMs));
                    o.put("live", nodeAtLive(x, y));
                    o.put("t_done_ms", r1(monoMs()));
                    out.reply(o);
                } catch (Throwable t) {
                    errorLine(null, "touch_node", t);
                }
            });
        } catch (RejectedExecutionException e) {
            errorLine(null, "touch_node", new IllegalStateException("touch resolver overloaded"));
        }
    }
}
