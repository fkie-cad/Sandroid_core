package sandroid.uihelper;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.UiAutomation;
import android.os.HandlerThread;
import android.os.Looper;
import android.view.accessibility.AccessibilityEvent;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Owns the single UiAutomation connection (the same mechanism {@code uiautomator}
 * uses: {@code new UiAutomation(looper, new UiAutomationConnection()).connect(flags)},
 * both hidden, so reflection). Android allows exactly one UiAutomation per device;
 * a second {@link #connect()} fails with "already registered" which we surface as
 * {@code busy}.
 *
 * <p>Two modes, chosen once at startup by the connect flags:
 * <ul>
 *   <li>{@link #FLAG_FULL} ({@code FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES}): a
 *       registered a11y client (events, windows, node queries). Visible to apps:
 *       {@code accessibility_enabled} reads 1 while connected.
 *   <li>{@link #FLAG_INVISIBLE} ({@code FLAG_DONT_USE_ACCESSIBILITY}): no a11y
 *       registration at all, so no events or node queries, but
 *       {@code takeScreenshot()} still works and nothing is visible to apps.
 * </ul>
 */
final class Uia {
    interface EventSink {
        /** Called on the a11y looper thread with a private copy of the event. */
        void onEvent(AccessibilityEvent copy);
    }

    /** {@code UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES}. */
    static final int FLAG_FULL = 1;
    /** {@code UiAutomation.FLAG_DONT_USE_ACCESSIBILITY} (hidden, API 30+). */
    static final int FLAG_INVISIBLE = 2;

    private final HandlerThread thread = new HandlerThread("uihelper-a11y");
    private final EventSink sink;
    final int flags;
    private volatile UiAutomation ua;
    private volatile boolean includeNotImportant;
    volatile int connects;
    volatile String lastError;

    Uia(EventSink sink, boolean includeNotImportant, int flags) {
        this.sink = sink;
        this.flags = flags;
        this.includeNotImportant = includeNotImportant;
        thread.start();
    }

    UiAutomation get() {
        UiAutomation u = ua;
        if (u == null) {
            throw new IllegalStateException("UiAutomation not connected");
        }
        return u;
    }

    boolean isConnected() {
        return ua != null;
    }

    /** False in invisible mode: no events, windows or node queries exist. */
    boolean usesA11y() {
        return (flags & FLAG_INVISIBLE) == 0;
    }

    /** Connects; throws with a readable message (e.g. busy) on failure. */
    synchronized void connect() throws Exception {
        disconnect();
        Looper looper = thread.getLooper();
        Class<?> connCls = Class.forName("android.app.UiAutomationConnection");
        Class<?> iconn = Class.forName("android.app.IUiAutomationConnection");
        Constructor<?> cc = connCls.getDeclaredConstructor();
        cc.setAccessible(true);
        Object conn = cc.newInstance();
        UiAutomation u;
        try {
            Constructor<UiAutomation> uc = UiAutomation.class.getDeclaredConstructor(Looper.class, iconn);
            uc.setAccessible(true);
            u = uc.newInstance(looper, conn);
        } catch (NoSuchMethodException e) {
            // Fallback for builds that only keep the private (displayId, looper, conn) form.
            Constructor<UiAutomation> uc = UiAutomation.class.getDeclaredConstructor(int.class, Looper.class, iconn);
            uc.setAccessible(true);
            u = uc.newInstance(0, looper, conn);
        }
        try {
            Method m = UiAutomation.class.getDeclaredMethod("connect", int.class);
            m.setAccessible(true);
            // FULL keeps TalkBack & co. running: the default (0) suppresses them,
            // which is both intrusive and a detectability signal. INVISIBLE does
            // not register with the a11y manager at all.
            m.invoke(u, flags);
        } catch (NoSuchMethodException e) {
            if (!usesA11y()) {
                throw new IllegalStateException("connect(flags) unavailable: invisible mode unsupported");
            }
            Method m = UiAutomation.class.getDeclaredMethod("connect");
            m.setAccessible(true);
            m.invoke(u);
        } catch (InvocationTargetException e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            lastError = String.valueOf(c.getMessage());
            throw new IllegalStateException(c.getClass().getSimpleName() + ": " + c.getMessage(), c);
        }
        if (usesA11y()) {
            u.setOnAccessibilityEventListener(new UiAutomation.OnAccessibilityEventListener() {
                @Override
                public void onAccessibilityEvent(AccessibilityEvent event) {
                    @SuppressWarnings("deprecation")
                    AccessibilityEvent copy = AccessibilityEvent.obtain(event);
                    sink.onEvent(copy);
                }
            });
        }
        ua = u;
        if (usesA11y()) {
            applyServiceInfo();
        }
        connects++;
        lastError = null;
    }

    synchronized void setIncludeNotImportant(boolean v) {
        includeNotImportant = v;
        if (ua != null && usesA11y()) {
            applyServiceInfo();
        }
    }

    boolean includeNotImportant() {
        return includeNotImportant;
    }

    private void applyServiceInfo() {
        UiAutomation u = get();
        AccessibilityServiceInfo info = u.getServiceInfo();
        if (info == null) {
            info = new AccessibilityServiceInfo();
        }
        info.eventTypes = AccessibilityEvent.TYPES_ALL_MASK;
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        int flags = info.flags
                | AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                | AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
        if (includeNotImportant) {
            flags |= AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
        } else {
            flags &= ~AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
        }
        info.flags = flags;
        u.setServiceInfo(info);
        // Flag changes alter which nodes exist; drop the client-side node cache.
        try {
            u.clearCache();
        } catch (Throwable ignored) {
            // API < 34
        }
    }

    /** True when the connection still answers (detects a dropped service). */
    boolean healthy() {
        UiAutomation u = ua;
        if (u == null) {
            return false;
        }
        if (!usesA11y()) {
            return true; // no a11y registration to lose
        }
        try {
            return u.getServiceInfo() != null;
        } catch (Throwable t) {
            return false;
        }
    }

    synchronized void disconnect() {
        UiAutomation u = ua;
        ua = null;
        if (u == null) {
            return;
        }
        try {
            if (usesA11y()) {
                u.setOnAccessibilityEventListener(null);
            }
        } catch (Throwable ignored) {
            // already gone
        }
        try {
            Method m = UiAutomation.class.getDeclaredMethod("disconnect");
            m.setAccessible(true);
            m.invoke(u);
        } catch (Throwable ignored) {
            // already disconnected
        }
    }

    /** Test hook: drop the connection behind the watchdog's back. */
    void simulateLoss() {
        UiAutomation u = ua;
        if (u == null) {
            return;
        }
        try {
            Method m = UiAutomation.class.getDeclaredMethod("disconnect");
            m.setAccessible(true);
            m.invoke(u);
        } catch (Throwable ignored) {
            // nothing to do
        }
    }
}
