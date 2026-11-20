package sandroid.uihelper;

import android.graphics.Rect;
import android.graphics.Region;
import android.os.Build;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Accessibility-tree model shared by the live hit test, the cached snapshots and
 * {@code dump}.
 *
 * <p>An {@link SNode} is a plain copy of the fields Sandroid cares about. A live
 * query keeps the backing {@link AccessibilityNodeInfo} and loads children lazily
 * (only the branch under the finger costs IPC); a snapshot loads everything
 * up-front and then drops the backing infos so it can be queried later, after
 * the UI has moved on.
 */
final class Tree {
    private Tree() {}

    /** Limits applied while copying a tree. */
    static final class Limits {
        int maxNodes = 4000;
        long maxMs = 2500;
        int textMax = 500;
        boolean visibleOnly = true; // invisible subtrees can be 50x the visible tree (WebView)
        int maxDepth = 0; // 0 = unlimited
    }

    // ------------------------------------------------------------------ model

    static final class SWindow {
        int id;
        int type;
        int layer;
        int displayId;
        String title;
        Rect bounds = new Rect();
        Region region; // API 33+, may be null
        boolean focused;
        boolean active;
        boolean pip;
        SNode root; // null when the window had no root (transition, secure, ...)
        boolean truncated;

        boolean contains(int x, int y) {
            if (region != null && !region.isEmpty()) {
                return region.contains(x, y);
            }
            return bounds.contains(x, y);
        }
    }

    static final class SNode {
        int windowId;
        long nid; // AccessibilityNodeInfo source id (stable while the view lives)
        String pkg;
        String cls;
        String text;
        String desc;
        String rid;
        String hint;
        String pane;
        String state;
        String tooltip;
        Rect b = new Rect();
        boolean visible;
        boolean clickable;
        boolean longClickable;
        boolean editable;
        boolean password;
        boolean checkable;
        boolean checked;
        boolean enabled;
        boolean focusable;
        boolean focused;
        boolean selected;
        boolean scrollable;
        boolean clickAction; // ACTION_CLICK advertised (Compose often relies on it)
        boolean important = true;
        int drawingOrder;
        int index;
        int depth;
        int childCount;
        boolean showingHint;
        // Web content (from the node's extras, parcelled with it: no extra IPC).
        String engine; // chromium | gecko (null: not web content)
        String role; // chromeRole / geckoRole
        String roleDesc;
        String href; // Chromium targetUrl of a link
        String fieldLabel; // Chromium SUPPLEMENTAL_DESCRIPTION_KEY, else the hint
        int inputType;
        SNode parent;
        SNode[] kids; // null = not loaded yet (live mode only)
        AccessibilityNodeInfo info; // only while live

        boolean actionable() {
            return clickable || longClickable || editable || checkable || clickAction;
        }
    }

    // ------------------------------------------------------------- reflection

    private static final Method GET_SOURCE_NODE_ID = findMethod(
            AccessibilityNodeInfo.class, "getSourceNodeId");

    private static Method findMethod(Class<?> c, String name, Class<?>... args) {
        try {
            Method m = c.getDeclaredMethod(name, args);
            m.setAccessible(true);
            return m;
        } catch (Throwable t) {
            return null;
        }
    }

    static long sourceNodeId(AccessibilityNodeInfo n) {
        if (GET_SOURCE_NODE_ID != null) {
            try {
                return (Long) GET_SOURCE_NODE_ID.invoke(n);
            } catch (Throwable ignored) {
                // fall through
            }
        }
        return n.hashCode();
    }

    // ----------------------------------------------------------------- copy

    static String str(CharSequence cs, int max) {
        if (cs == null) {
            return null;
        }
        String s = cs.toString();
        if (s.isEmpty()) {
            return null;
        }
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    /** Copy one node's own fields (no children). */
    static SNode copy(AccessibilityNodeInfo n, int windowId, int depth, int index, int textMax) {
        SNode s = new SNode();
        s.windowId = windowId;
        s.nid = sourceNodeId(n);
        s.pkg = str(n.getPackageName(), 200);
        s.cls = str(n.getClassName(), 200);
        s.text = str(n.getText(), textMax);
        s.desc = str(n.getContentDescription(), textMax);
        s.rid = str(n.getViewIdResourceName(), 300);
        if (Build.VERSION.SDK_INT >= 26) {
            s.hint = str(n.getHintText(), textMax);
        }
        if (Build.VERSION.SDK_INT >= 28) {
            s.pane = str(n.getPaneTitle(), textMax);
            s.tooltip = str(n.getTooltipText(), textMax);
        }
        if (Build.VERSION.SDK_INT >= 30) {
            s.state = str(n.getStateDescription(), textMax);
        }
        n.getBoundsInScreen(s.b);
        s.visible = n.isVisibleToUser();
        s.clickable = n.isClickable();
        s.longClickable = n.isLongClickable();
        s.editable = n.isEditable();
        s.password = n.isPassword();
        s.checkable = n.isCheckable();
        s.checked = n.isChecked();
        s.enabled = n.isEnabled();
        s.focusable = n.isFocusable();
        s.focused = n.isFocused();
        s.selected = n.isSelected();
        s.scrollable = n.isScrollable();
        if (!s.clickable) {
            List<AccessibilityNodeInfo.AccessibilityAction> acts = n.getActionList();
            if (acts != null) {
                for (AccessibilityNodeInfo.AccessibilityAction a : acts) {
                    if (a.getId() == AccessibilityNodeInfo.ACTION_CLICK) {
                        s.clickAction = true;
                        break;
                    }
                }
            }
        }
        s.drawingOrder = Build.VERSION.SDK_INT >= 24 ? n.getDrawingOrder() : 0;
        if (Build.VERSION.SDK_INT >= 24) {
            s.important = n.isImportantForAccessibility();
        }
        s.index = index;
        s.depth = depth;
        s.childCount = n.getChildCount();
        if (Build.VERSION.SDK_INT >= 26) {
            s.showingHint = n.isShowingHintText();
        }
        web(n, s, textMax);
        return s;
    }

    // ------------------------------------------------------------------ web

    static final String K_CHROME_ROLE = "AccessibilityNodeInfo.chromeRole";
    static final String K_GECKO_ROLE = "AccessibilityNodeInfo.geckoRole";
    static final String K_ROLE_DESC = "AccessibilityNodeInfo.roleDescription";
    static final String K_TARGET_URL = "AccessibilityNodeInfo.targetUrl";
    static final String K_SUPPL =
            "androidx.view.accessibility.AccessibilityNodeInfoCompat.SUPPLEMENTAL_DESCRIPTION_KEY";

    /** Roles that name nothing (a tap on them means their interactive ancestor). */
    private static final java.util.Set<String> GENERIC = new java.util.HashSet<>(Arrays.asList(
            "section", "genericContainer", "text leaf", "staticText", "paragraph", "generic",
            "none", "inlineTextBox", "text", "group", "presentational"));

    /** Chromium and Gecko roles of controls a user operates. */
    private static final java.util.Set<String> INTERACTIVE = new java.util.HashSet<>(Arrays.asList(
            // Chromium (ax::mojom::Role)
            "button", "link", "textField", "textFieldWithComboBox", "searchBox", "checkBox",
            "radioButton", "switch", "comboBoxSelect", "comboBoxMenuButton", "comboBoxGrouping",
            "popUpButton", "menuItem", "menuItemCheckBox", "menuItemRadio", "menuListOption",
            "listBoxOption", "tab", "toggleButton", "slider", "spinButton", "treeItem",
            "disclosureTriangle", "date", "dateTime", "inputTime", "colorWell",
            // Gecko (nsIAccessibleRole names)
            "pushbutton", "entry", "password text", "combobox", "combobox option", "checkbutton",
            "radiobutton", "toggle button", "menuitem", "check menu item", "radio menu item",
            "option", "page tab", "spinbutton", "buttonmenu", "buttondropdown", "parent menuitem",
            "outlineitem", "summary"));

    private static String extra(android.os.Bundle b, String key, int max) {
        Object v = b.get(key);
        return v == null ? null : str(String.valueOf(v), max);
    }

    /** Web fields from the node's extras (Chrome / WebView: chromeRole; Firefox: geckoRole). */
    static void web(AccessibilityNodeInfo n, SNode s, int textMax) {
        try {
            s.inputType = n.getInputType();
            android.os.Bundle b = n.getExtras();
            if (b == null || b.isEmpty()) {
                return;
            }
            if (b.containsKey(K_CHROME_ROLE)) {
                s.engine = "chromium";
                s.role = extra(b, K_CHROME_ROLE, 60);
            } else if (b.containsKey(K_GECKO_ROLE)) {
                s.engine = "gecko";
                s.role = extra(b, K_GECKO_ROLE, 60);
            } else {
                return;
            }
            s.roleDesc = extra(b, K_ROLE_DESC, 60);
            s.href = extra(b, K_TARGET_URL, 1000);
            s.fieldLabel = extra(b, K_SUPPL, textMax);
            if (s.fieldLabel == null) {
                s.fieldLabel = s.hint; // Gecko puts a field's label into the hint
            }
        } catch (Throwable ignored) {
            // a malformed bundle: no web fields
        }
    }

    static boolean genericWeb(SNode s) {
        return s.engine != null && (s.role == null || GENERIC.contains(s.role));
    }

    static boolean interactiveWeb(SNode s) {
        return s.engine != null && s.role != null && INTERACTIVE.contains(s.role);
    }

    /**
     * A web hit with a generic role (a span inside a button, the text of a
     * link): its nearest ancestor with an interactive role, at most 3 levels
     * up; null when there is none (or the hit is not generic web content).
     */
    static SNode webControl(SNode hit) {
        if (hit == null || !genericWeb(hit)) {
            return null;
        }
        SNode s = hit.parent;
        for (int i = 0; i < 3 && s != null; i++, s = s.parent) {
            if (interactiveWeb(s)) {
                return s;
            }
            if (s.engine == null) {
                break; // left the web content
            }
        }
        return null;
    }

    /** A web document root: Chromium rootWebArea, Gecko document (or its WebView). */
    static boolean webDocument(SNode s) {
        if (s.engine == null) {
            return false;
        }
        if ("rootWebArea".equals(s.role) || "document".equals(s.role)) {
            return true;
        }
        return "gecko".equals(s.engine) && "android.webkit.WebView".equals(s.cls);
    }

    /** The title of a web document node. */
    static String webTitle(SNode s) {
        if ("chromium".equals(s.engine) && s.fieldLabel != null) {
            return s.fieldLabel;
        }
        return s.text != null ? s.text : s.desc;
    }

    /**
     * Nothing under the finger but the web container itself: a WebView,
     * a document root, Firefox's engineView (Gecko builds the tree lazily),
     * or Chrome's compositor view without its web content (Chrome drops the
     * page's tree while no accessibility client asked for a while).
     */
    static boolean bareWeb(SNode h) {
        if (h == null) {
            return false;
        }
        if ("android.webkit.WebView".equals(h.cls) || webDocument(h)) {
            return true;
        }
        if (h.rid != null && h.rid.endsWith(":id/engineView")) {
            return true;
        }
        if (h.engine != null) {
            return false;
        }
        SNode s = h;
        for (int i = 0; i < 3 && s != null; i++, s = s.parent) {
            if (s.rid != null && s.rid.endsWith(":id/compositor_view_holder")) {
                return true;
            }
        }
        return false;
    }

    static SWindow copyWindow(AccessibilityWindowInfo w) {
        SWindow sw = new SWindow();
        sw.id = w.getId();
        sw.type = w.getType();
        sw.layer = w.getLayer();
        w.getBoundsInScreen(sw.bounds);
        sw.focused = w.isFocused();
        sw.active = w.isActive();
        if (Build.VERSION.SDK_INT >= 24) {
            sw.title = str(w.getTitle(), 200);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            sw.pip = w.isInPictureInPictureMode();
        }
        if (Build.VERSION.SDK_INT >= 30) {
            sw.displayId = w.getDisplayId();
        }
        if (Build.VERSION.SDK_INT >= 33) {
            Region r = new Region();
            w.getRegionInScreen(r);
            sw.region = r;
        }
        return sw;
    }

    /** Prefetch strategy for getRoot(): pull a hybrid batch of descendants per IPC. */
    static AccessibilityNodeInfo rootOf(AccessibilityWindowInfo w) {
        if (Build.VERSION.SDK_INT >= 33) {
            return w.getRoot(AccessibilityNodeInfo.FLAG_PREFETCH_DESCENDANTS_HYBRID);
        }
        return w.getRoot();
    }

    /** Load (and cache) the children of a live node. */
    static SNode[] kids(SNode n, int textMax) {
        if (n.kids != null) {
            return n.kids;
        }
        if (n.info == null) {
            n.kids = new SNode[0];
            return n.kids;
        }
        int cc = n.info.getChildCount();
        ArrayList<SNode> out = new ArrayList<>(cc);
        for (int i = 0; i < cc; i++) {
            AccessibilityNodeInfo c = n.info.getChild(i);
            if (c == null) {
                continue;
            }
            SNode sc = copy(c, n.windowId, n.depth + 1, i, textMax);
            sc.parent = n;
            sc.info = c;
            out.add(sc);
        }
        n.kids = out.toArray(new SNode[0]);
        return n.kids;
    }

    /** Fully copy a subtree breadth-first, honouring node/time limits. */
    static boolean copyAll(SNode root, Limits lim, int[] budget, long deadlineNs) {
        ArrayList<SNode> queue = new ArrayList<>();
        queue.add(root);
        boolean truncated = false;
        for (int qi = 0; qi < queue.size(); qi++) {
            SNode n = queue.get(qi);
            if (budget[0] <= 0 || System.nanoTime() > deadlineNs) {
                n.kids = new SNode[0];
                truncated = true;
                continue;
            }
            if (lim.maxDepth > 0 && n.depth >= lim.maxDepth) {
                n.kids = new SNode[0];
                truncated |= n.childCount > 0;
                continue;
            }
            SNode[] ks = kids(n, lim.textMax);
            if (lim.visibleOnly) {
                ArrayList<SNode> vis = new ArrayList<>(ks.length);
                for (SNode k : ks) {
                    if (k.visible) {
                        vis.add(k);
                    }
                }
                if (vis.size() != ks.length) {
                    ks = vis.toArray(new SNode[0]);
                    n.kids = ks;
                }
            }
            budget[0] -= ks.length;
            queue.addAll(Arrays.asList(ks));
        }
        for (SNode n : queue) {
            n.info = null; // snapshot: detach from the live tree
            if (n.kids == null) {
                n.kids = new SNode[0];
            }
        }
        return truncated;
    }

    /** Windows sorted top-most first. */
    static List<AccessibilityWindowInfo> zOrder(List<AccessibilityWindowInfo> ws) {
        ArrayList<AccessibilityWindowInfo> out = new ArrayList<>(ws);
        out.sort(new Comparator<AccessibilityWindowInfo>() {
            @Override
            public int compare(AccessibilityWindowInfo a, AccessibilityWindowInfo b) {
                return Integer.compare(b.getLayer(), a.getLayer());
            }
        });
        return out;
    }

    // ------------------------------------------------------------- hit test

    /** Children containing (x,y), top-most first (drawing order, then index). */
    private static SNode[] under(SNode n, int x, int y, int textMax) {
        SNode[] ks = kids(n, textMax);
        ArrayList<SNode> hit = new ArrayList<>();
        for (SNode k : ks) {
            if (k.visible && !k.b.isEmpty() && k.b.contains(x, y)) {
                hit.add(k);
            }
        }
        hit.sort(new Comparator<SNode>() {
            @Override
            public int compare(SNode a, SNode b) {
                int c = Integer.compare(b.drawingOrder, a.drawingOrder);
                return c != 0 ? c : Integer.compare(b.index, a.index);
            }
        });
        return hit.toArray(new SNode[0]);
    }

    private static boolean actionableBetween(SNode deep, SNode top) {
        for (SNode s = deep; s != null; s = s.parent) {
            if (s.actionable()) {
                return true;
            }
            if (s == top) {
                break;
            }
        }
        return false;
    }

    /**
     * Deepest visible node under (x,y). Among overlapping siblings the top-most
     * branch that contains an actionable node wins (roughly how touch dispatch
     * picks the view that consumes the tap); otherwise the top-most branch.
     */
    static SNode hit(SNode n, int x, int y, int textMax) {
        SNode[] cand = under(n, x, y, textMax);
        if (cand.length == 0) {
            return n;
        }
        SNode fallback = null;
        for (SNode c : cand) {
            SNode r = hit(c, x, y, textMax);
            if (actionableBetween(r, c)) {
                return r;
            }
            if (fallback == null) {
                fallback = r;
            }
        }
        return fallback;
    }

    static SNode target(SNode deep) {
        for (SNode s = deep; s != null; s = s.parent) {
            if (s.actionable()) {
                return s;
            }
        }
        return null;
    }

    /** Aggregated text/desc of a subtree (bounded), like what a user reads on a button. */
    static String label(SNode n, int textMax, int maxNodes, int maxLen) {
        StringBuilder sb = new StringBuilder();
        ArrayList<SNode> stack = new ArrayList<>();
        stack.add(n);
        int seen = 0;
        String last = null;
        while (!stack.isEmpty() && seen < maxNodes && sb.length() < maxLen) {
            SNode s = stack.remove(stack.size() - 1);
            seen++;
            String t = s.text != null ? s.text : s.desc;
            if (t != null && !t.equals(last)) {
                if (sb.length() > 0) {
                    sb.append(" / ");
                }
                sb.append(t);
                last = t;
            }
            SNode[] ks = kids(s, textMax);
            for (int i = ks.length - 1; i >= 0; i--) {
                if (ks[i].visible) {
                    stack.add(ks[i]);
                }
            }
        }
        if (sb.length() == 0) {
            return null;
        }
        return sb.length() > maxLen ? sb.substring(0, maxLen) + "…" : sb.toString();
    }

    // ----------------------------------------------------------------- JSON

    static final String[] WINDOW_TYPES = {
        "?", "app", "ime", "system", "a11y_overlay", "split_divider", "magnification"
    };

    static String windowType(int t) {
        return t >= 0 && t < WINDOW_TYPES.length ? WINDOW_TYPES[t] : "type" + t;
    }

    static JSONArray rect(Rect r) throws JSONException {
        return new JSONArray().put(r.left).put(r.top).put(r.right).put(r.bottom);
    }

    static JSONObject windowJson(SWindow w, int screenW, int screenH) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", w.id);
        o.put("type", windowType(w.type));
        o.putOpt("title", w.title);
        o.put("layer", w.layer);
        o.put("bounds", rect(w.bounds));
        if (w.focused) {
            o.put("focused", true);
        }
        if (w.active) {
            o.put("active", true);
        }
        if (w.pip) {
            o.put("pip", true);
        }
        if (w.displayId != 0) {
            o.put("display", w.displayId);
        }
        if (w.type == AccessibilityWindowInfo.TYPE_APPLICATION && screenW > 0
                && (w.bounds.width() < screenW * 0.95 || w.bounds.height() < screenH * 0.85)) {
            o.put("dialog_like", true);
        }
        if (w.root != null) {
            o.putOpt("pkg", w.root.pkg);
        }
        return o;
    }

    static JSONObject nodeJson(SNode n) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("nid", n.nid);
        o.putOpt("cls", n.cls);
        o.putOpt("text", n.text);
        o.putOpt("desc", n.desc);
        o.putOpt("rid", n.rid);
        o.putOpt("hint", n.hint);
        o.putOpt("pane", n.pane);
        o.putOpt("state", n.state);
        o.putOpt("tooltip", n.tooltip);
        o.put("bounds", rect(n.b));
        flag(o, "clickable", n.clickable);
        flag(o, "long_clickable", n.longClickable);
        flag(o, "click_action", n.clickAction && !n.clickable);
        flag(o, "editable", n.editable);
        flag(o, "password", n.password);
        flag(o, "checkable", n.checkable);
        flag(o, "checked", n.checked);
        flag(o, "focused", n.focused);
        flag(o, "selected", n.selected);
        flag(o, "scrollable", n.scrollable);
        if (!n.enabled) {
            o.put("enabled", false);
        }
        if (!n.visible) {
            o.put("visible", false);
        }
        if (!n.important) {
            o.put("important", false);
        }
        if (n.drawingOrder != 0) {
            o.put("z", n.drawingOrder);
        }
        flag(o, "showing_hint", n.showingHint);
        if (n.engine != null) {
            JSONObject w = new JSONObject();
            w.put("engine", n.engine);
            w.putOpt("role", n.role);
            w.putOpt("role_desc", n.roleDesc);
            w.putOpt("href", n.href);
            w.putOpt("label", n.fieldLabel);
            if (n.inputType != 0) {
                w.put("input_type", n.inputType);
            }
            o.put("web", w);
        } else if (n.inputType != 0) {
            o.put("input_type", n.inputType);
        }
        return o;
    }

    private static void flag(JSONObject o, String k, boolean v) throws JSONException {
        if (v) {
            o.put(k, true);
        }
    }

    /** Nested tree for dump. Packages are only emitted where they change. */
    static JSONObject treeJson(SNode n, String parentPkg) throws JSONException {
        JSONObject o = nodeJson(n);
        if (n.pkg != null && !n.pkg.equals(parentPkg)) {
            o.put("pkg", n.pkg);
        }
        if (n.kids != null && n.kids.length > 0) {
            JSONArray a = new JSONArray();
            for (SNode k : n.kids) {
                a.put(treeJson(k, n.pkg != null ? n.pkg : parentPkg));
            }
            o.put("kids", a);
        }
        return o;
    }

    /** Short ancestry chain "cls#rid" from the window root to the node. */
    static JSONArray path(SNode n) {
        ArrayList<String> parts = new ArrayList<>();
        for (SNode s = n; s != null; s = s.parent) {
            String c = s.cls == null ? "?" : s.cls.substring(s.cls.lastIndexOf('.') + 1);
            if (s.rid != null) {
                c += "#" + s.rid.substring(s.rid.indexOf('/') + 1);
            }
            parts.add(c);
        }
        JSONArray a = new JSONArray();
        for (int i = parts.size() - 1; i >= 0; i--) {
            a.put(parts.get(i));
        }
        return a;
    }
}
