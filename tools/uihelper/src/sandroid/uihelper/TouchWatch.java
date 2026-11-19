package sandroid.uihelper;

import android.os.Process;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Tap-time strategy (c): read the touchscreen evdev node directly (shell is in
 * the {@code input} group; evdev is multi-reader, nothing is grabbed or consumed)
 * and resolve the element on finger-down inside the helper, with no adb round
 * trip. Multi-touch protocol B only (emulator virtio-touch and practically all
 * phones).
 */
final class TouchWatch implements Runnable {
    interface Sink {
        /** Finger down at screen (x,y); {@code tMs} = device-monotonic kernel time. */
        void onDown(int slot, double tMs, int x, int y, int rawX, int rawY, boolean uncertain);

        void onUp(int slot, double tMs, double downMs, int x0, int y0, int x1, int y1, int maxMovePx);
    }

    private static final int EV_SYN = 0;
    private static final int EV_ABS = 3;
    private static final int SYN_REPORT = 0;
    private static final int ABS_MT_SLOT = 0x2f;
    private static final int ABS_MT_POSITION_X = 0x35;
    private static final int ABS_MT_POSITION_Y = 0x36;
    private static final int ABS_MT_TRACKING_ID = 0x39;
    private static final int MAX_SLOTS = 16;

    private final String path;
    private int maxX;
    private int maxY;
    private final Sink sink;
    private final Main.Display display;
    private volatile boolean stop;
    private volatile InputStream in;
    private Thread thread;
    volatile String error;
    volatile Boolean realtimeClock; // evdev defaults to CLOCK_REALTIME unless EVIOCSCLOCKID

    private final int[] rx = new int[MAX_SLOTS];
    private final int[] ry = new int[MAX_SLOTS];
    private final int[] tid = new int[MAX_SLOTS];
    private final boolean[] pendingDown = new boolean[MAX_SLOTS];
    private final boolean[] pendingUp = new boolean[MAX_SLOTS];
    private final double[] downAt = new double[MAX_SLOTS];
    private final int[] x0 = new int[MAX_SLOTS];
    private final int[] y0 = new int[MAX_SLOTS];
    private final int[] lastX = new int[MAX_SLOTS];
    private final int[] lastY = new int[MAX_SLOTS];
    private final int[] maxMove = new int[MAX_SLOTS];
    // The kernel drops axis values equal to the slot's previous one, so until we have
    // seen X and Y for a slot, its position may be stale (EVIOCGMTSLOTS needs JNI).
    private final boolean[] seenX = new boolean[MAX_SLOTS];
    private final boolean[] seenY = new boolean[MAX_SLOTS];

    TouchWatch(String path, int maxX, int maxY, Main.Display display, Sink sink) {
        this.path = path;
        this.maxX = Math.max(1, maxX);
        this.maxY = Math.max(1, maxY);
        this.display = display;
        this.sink = sink;
        java.util.Arrays.fill(tid, -1);
    }

    /** Probe result: touchscreen node with its axis ranges and current values. */
    static final class Probe {
        String path;
        int maxX = -1;
        int maxY = -1;
        int curX;
        int curY;
    }

    /**
     * {@code getevent -p} gives what Java cannot ioctl: ABS ranges, and the current
     * MT position (the kernel drops unchanged axis values, so the first touch after
     * we open the node may carry no X or Y at all). {@code want} null = first device
     * with ABS_MT_POSITION_X.
     */
    static Probe probe(String want) {
        Probe best = null;
        Probe cur = null;
        java.util.regex.Pattern dev = java.util.regex.Pattern.compile("add device \\d+: (\\S+)");
        java.util.regex.Pattern abs = java.util.regex.Pattern.compile(
                "\\b(0035|0036)\\s*: value (-?\\d+), min -?\\d+, max (-?\\d+)");
        try {
            java.lang.Process p = Runtime.getRuntime().exec(
                    want == null ? new String[] {"getevent", "-p"} : new String[] {"getevent", "-p", want});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                java.util.regex.Matcher m = dev.matcher(line);
                if (m.find()) {
                    if (cur != null && cur.maxX > 0 && best == null) {
                        best = cur;
                    }
                    cur = new Probe();
                    cur.path = m.group(1);
                    continue;
                }
                m = abs.matcher(line);
                if (m.find() && cur != null) {
                    int v = Integer.parseInt(m.group(2));
                    int max = Integer.parseInt(m.group(3));
                    if (m.group(1).equals("0035")) {
                        cur.curX = v;
                        cur.maxX = max;
                    } else {
                        cur.curY = v;
                        cur.maxY = max;
                    }
                }
            }
            p.waitFor();
        } catch (Exception e) {
            return best;
        }
        if (best == null && cur != null && cur.maxX > 0) {
            best = cur;
        }
        return best;
    }

    /** Seed the last-known position (see {@link #probe}). */
    void seed(Probe p) {
        if (p == null) {
            return;
        }
        // Note: getevent -p reports absinfo.value, which the kernel does not update for
        // MT slot axes, so it cannot seed the position; only the ranges are used.
        if (p.maxX > 0) {
            maxX = p.maxX;
        }
        if (p.maxY > 0) {
            maxY = p.maxY;
        }
    }

    String path() {
        return path;
    }

    int maxX() {
        return maxX;
    }

    int maxY() {
        return maxY;
    }

    void start() {
        thread = new Thread(this, "uihelper-touch");
        thread.setDaemon(true);
        thread.setPriority(Thread.MAX_PRIORITY);
        thread.start();
    }

    void stop() {
        stop = true;
        InputStream s = in;
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // closing
            }
        }
        if (thread != null) {
            thread.interrupt();
        }
    }

    @Override
    public void run() {
        boolean is64 = Process.is64Bit();
        int recSize = is64 ? 24 : 16;
        byte[] buf = new byte[recSize * 64];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        int slot = 0;
        try (FileInputStream fis = new FileInputStream(path)) {
            in = fis;
            int have = 0;
            while (!stop) {
                int n = fis.read(buf, have, buf.length - have);
                if (n < 0) {
                    break;
                }
                have += n;
                int off = 0;
                while (have - off >= recSize) {
                    long sec = is64 ? bb.getLong(off) : bb.getInt(off) & 0xffffffffL;
                    long usec = is64 ? bb.getLong(off + 8) : bb.getInt(off + 4) & 0xffffffffL;
                    int p = off + (is64 ? 16 : 8);
                    int type = bb.getShort(p) & 0xffff;
                    int code = bb.getShort(p + 2) & 0xffff;
                    int value = bb.getInt(p + 4);
                    off += recSize;
                    double t = toMono(sec * 1000.0 + usec / 1000.0);
                    if (type == EV_ABS) {
                        if (code == ABS_MT_SLOT) {
                            slot = (value >= 0 && value < MAX_SLOTS) ? value : 0;
                        } else if (code == ABS_MT_TRACKING_ID) {
                            if (value >= 0) {
                                tid[slot] = value;
                                pendingDown[slot] = true;
                                downAt[slot] = t;
                            } else if (tid[slot] >= 0) {
                                tid[slot] = -1;
                                pendingUp[slot] = true;
                            }
                        } else if (code == ABS_MT_POSITION_X) {
                            rx[slot] = value;
                            seenX[slot] = true;
                        } else if (code == ABS_MT_POSITION_Y) {
                            ry[slot] = value;
                            seenY[slot] = true;
                        }
                    } else if (type == EV_SYN && code == SYN_REPORT) {
                        frame(t);
                    }
                }
                System.arraycopy(buf, off, buf, 0, have - off);
                have -= off;
            }
        } catch (IOException e) {
            if (!stop) {
                error = e.toString();
            }
        } finally {
            in = null;
        }
    }

    private double toMono(double evMs) {
        double mono = Main.monoMs();
        if (realtimeClock == null) {
            double wall = System.currentTimeMillis();
            realtimeClock = Math.abs(evMs - wall) < Math.abs(evMs - mono);
        }
        if (realtimeClock) {
            return evMs - (System.currentTimeMillis() - mono);
        }
        return evMs;
    }

    private void frame(double t) {
        int[] scr = new int[2];
        for (int s = 0; s < MAX_SLOTS; s++) {
            if (tid[s] >= 0 || pendingUp[s]) {
                toScreen(rx[s], ry[s], scr);
                if (pendingDown[s]) {
                    pendingDown[s] = false;
                    x0[s] = scr[0];
                    y0[s] = scr[1];
                    maxMove[s] = 0;
                    sink.onDown(s, downAt[s], scr[0], scr[1], rx[s], ry[s], !(seenX[s] && seenY[s]));
                }
                lastX[s] = scr[0];
                lastY[s] = scr[1];
                int mv = (int) Math.hypot(scr[0] - x0[s], scr[1] - y0[s]);
                if (mv > maxMove[s]) {
                    maxMove[s] = mv;
                }
                if (pendingUp[s]) {
                    pendingUp[s] = false;
                    sink.onUp(s, t, downAt[s], x0[s], y0[s], lastX[s], lastY[s], maxMove[s]);
                }
            }
        }
    }

    /** Raw panel coordinates (natural orientation) to current-rotation screen px. */
    private void toScreen(int rawX, int rawY, int[] out) {
        Main.Display d = display.refreshIfStale(500);
        boolean swapped = d.rotation == 1 || d.rotation == 3;
        int natW = swapped ? d.height : d.width;
        int natH = swapped ? d.width : d.height;
        double nx = (double) rawX * natW / maxX;
        double ny = (double) rawY * natH / maxY;
        double x;
        double y;
        switch (d.rotation) {
            case 1: // 90
                x = ny;
                y = natW - nx;
                break;
            case 2: // 180
                x = natW - nx;
                y = natH - ny;
                break;
            case 3: // 270
                x = natH - ny;
                y = nx;
                break;
            default:
                x = nx;
                y = ny;
        }
        out[0] = (int) Math.round(x);
        out[1] = (int) Math.round(y);
    }
}
