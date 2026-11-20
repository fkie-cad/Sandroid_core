package sandroid.worldhelper;

import android.accounts.Account;
import android.content.AttributionSource;
import android.content.ContentProviderOperation;
import android.content.ContentProviderResult;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileDescriptor;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sandroid world helper: seeds a device's content providers from ONE JVM.
 *
 * <p>Runs under {@code app_process} as root (adb root, zygote's env imported)
 * and speaks JSON lines: one request per stdin line
 * ({@code {"id": n, "cmd": ...}}), one reply per stdout line
 * ({@code {"id": n, "ok": true, ...}} or {@code {"id": n, "ok": false,
 * "error": ...}}). The first line is {@code {"type": "hello", ...}}.
 *
 * <p>Providers are reached like the {@code content} command does it:
 * {@code IActivityManager.getContentProviderExternal} and the provider's
 * binder interface with an AttributionSource for package "root". Every
 * insert reports the new row's {@code _id}; those ids are the host's ledger.
 */
public final class Main {
    static final String VERSION = "1.0.0";
    static final int PROTOCOL = 1;

    static final String CONTACTS = "com.android.contacts";
    static final String CALENDAR = "com.android.calendar";
    static final String CALL_LOG = "call_log";
    static final String SMS = "sms";

    static final String SEL = "android:query-arg-sql-selection";
    static final String SEL_ARGS = "android:query-arg-sql-selection-args";
    static final String SORT = "android:query-arg-sql-sort-order";
    static final Pattern ID_IN_LINE = Pattern.compile("\"id\"\\s*:\\s*(\\d+)");

    private final PrintStream out;
    private final Map<String, Object> providers = new HashMap<>();
    private final IBinder token = new Binder();
    private final AttributionSource source;
    private Object am;

    private Main(PrintStream out) {
        this.out = out;
        this.source = new AttributionSource.Builder(Process.myUid())
                .setPackageName(Process.myUid() == 0 ? "root" : "com.android.shell")
                .build();
    }

    public static void main(String[] args) {
        try {
            PrintStream ps = new PrintStream(
                    new FileOutputStream(FileDescriptor.out), true, "UTF-8");
            new Main(ps).run();
        } catch (Throwable t) {
            System.err.println("worldhelper fatal: " + t);
            t.printStackTrace();
            System.exit(2);
        }
    }

    private void run() throws Exception {
        am = Class.forName("android.app.ActivityManager").getMethod("getService").invoke(null);
        emit(new JSONObject()
                .put("type", "hello")
                .put("version", VERSION)
                .put("protocol", PROTOCOL)
                .put("sdk", Build.VERSION.SDK_INT)
                .put("pid", Process.myPid())
                .put("uid", Process.myUid()));
        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8), 1 << 16);
        String line;
        try {
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                JSONObject req;
                try {
                    req = new JSONObject(line);
                } catch (JSONException e) {
                    // Echo the request id when it can be found, so the host fails
                    // that request at once instead of waiting for its timeout.
                    Matcher m = ID_IN_LINE.matcher(line);
                    emit(new JSONObject()
                            .put("id", m.find() ? (Object) Long.parseLong(m.group(1)) : JSONObject.NULL)
                            .put("ok", false)
                            .put("error", "bad json: " + e.getMessage()));
                    continue;
                }
                Object id = req.opt("id");
                String cmd = req.optString("cmd");
                if ("quit".equals(cmd)) {
                    emit(new JSONObject().put("id", id).put("ok", true));
                    break;
                }
                long t0 = System.nanoTime();
                JSONObject reply;
                try {
                    reply = dispatch(cmd, req);
                    reply.put("ok", true);
                } catch (Throwable t) {
                    Throwable c = t;
                    while (c.getCause() != null && c != c.getCause()) c = c.getCause();
                    reply = new JSONObject().put("ok", false).put("error", String.valueOf(c));
                }
                reply.put("id", id);
                reply.put("ms", (System.nanoTime() - t0) / 1000000);
                emit(reply);
            }
        } finally {
            release();
        }
    }

    private synchronized void emit(JSONObject o) {
        out.println(o.toString());
        out.flush();
    }

    private JSONObject dispatch(String cmd, JSONObject req) throws Exception {
        switch (cmd) {
            case "ping":
                return new JSONObject().put("pong", true);
            case "contacts":
                return contacts(req.getJSONArray("items"));
            case "calendar":
                return calendar(req);
            case "calls":
                return calls(req.getJSONArray("items"));
            case "sms":
                return sms(req.getJSONArray("items"));
            case "sync_off":
                return syncOff(req);
            case "sync_state":
                return syncState(req);
            case "count":
                return count(req);
            case "delete":
                return delete(req);
            case "max_ids":
                return maxIds(req);
            case "delete_above":
                return deleteAbove(req);
            case "query":
                return query(req);
            default:
                throw new IllegalArgumentException("unknown cmd " + cmd);
        }
    }

    // ------------------------------------------------------------ providers

    private Object provider(String authority) throws Exception {
        Object p = providers.get(authority);
        if (p != null) return p;
        Method get = api(am, "android.app.IActivityManager").getMethod(
                "getContentProviderExternal",
                String.class, int.class, IBinder.class, String.class);
        Object holder = get.invoke(am, authority, 0, token, "sandroid-worldhelper");
        if (holder == null) throw new IllegalStateException("no provider " + authority);
        p = holder.getClass().getField("provider").get(holder);
        providers.put(authority, p);
        return p;
    }

    private void release() {
        for (String authority : providers.keySet()) {
            try {
                Method rm = api(am, "android.app.IActivityManager").getMethod(
                        "removeContentProviderExternalAsUser",
                        String.class, IBinder.class, int.class);
                rm.invoke(am, authority, token, 0);
            } catch (Throwable ignored) {
                // the process exits anyway
            }
        }
    }

    /** The public binder interface when it exists (its proxy class is private). */
    private static Class<?> api(Object target, String iface) {
        try {
            Class<?> c = Class.forName(iface);
            if (c.isInstance(target)) return c;
        } catch (ClassNotFoundException ignored) {
            // fall back to the object's own class
        }
        return target.getClass();
    }

    private static Method find(Object target, String name, int params) {
        for (Method m : api(target, "android.content.IContentProvider").getMethods()) {
            Class<?>[] t = m.getParameterTypes();
            if (m.getName().equals(name) && t.length == params && t.length > 0
                    && t[0] == AttributionSource.class) {
                return m;
            }
        }
        throw new IllegalStateException("no " + name + "/" + params + " on " + target.getClass());
    }

    private ContentProviderResult[] applyBatch(String authority,
            ArrayList<ContentProviderOperation> ops) throws Exception {
        Object p = provider(authority);
        return (ContentProviderResult[]) find(p, "applyBatch", 3).invoke(p, source, authority, ops);
    }

    private Uri insert(Uri uri, ContentValues cv) throws Exception {
        Object p = provider(uri.getAuthority());
        return (Uri) find(p, "insert", 4).invoke(p, source, uri, cv, null);
    }

    private Cursor queryCursor(Uri uri, String[] projection, String selection,
            String[] args, String sort) throws Exception {
        Object p = provider(uri.getAuthority());
        Bundle qa = new Bundle();
        if (selection != null) qa.putString(SEL, selection);
        if (args != null) qa.putStringArray(SEL_ARGS, args);
        if (sort != null) qa.putString(SORT, sort);
        return (Cursor) find(p, "query", 5).invoke(p, source, uri, projection, qa, null);
    }

    private int deleteRows(Uri uri, String selection, String[] args) throws Exception {
        Object p = provider(uri.getAuthority());
        Bundle extras = new Bundle();
        if (selection != null) extras.putString(SEL, selection);
        if (args != null) extras.putStringArray(SEL_ARGS, args);
        return (Integer) find(p, "delete", 3).invoke(p, source, uri, extras);
    }

    private static long idOf(Uri uri) {
        if (uri == null) return -1;
        try {
            return Long.parseLong(uri.getLastPathSegment());
        } catch (RuntimeException e) {
            return -1;
        }
    }

    // ---------------------------------------------------------------- seeding

    private static void put(ContentValues cv, String key, Object v) {
        if (v == null || v == JSONObject.NULL) cv.putNull(key);
        else if (v instanceof Integer) cv.put(key, (Integer) v);
        else if (v instanceof Long) cv.put(key, (Long) v);
        else if (v instanceof Double) cv.put(key, (Double) v);
        else if (v instanceof Boolean) cv.put(key, ((Boolean) v) ? 1 : 0);
        else cv.put(key, v.toString());
    }

    /** JSON object of column values to ContentValues (numbers stay numbers). */
    private static ContentValues values(JSONObject o) throws JSONException {
        ContentValues cv = new ContentValues();
        Iterator<String> keys = o.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            Object v = o.get(k);
            if (v instanceof Integer || v instanceof Long) {
                cv.put(k, ((Number) v).longValue());
            } else {
                put(cv, k, v);
            }
        }
        return cv;
    }

    private static ContentProviderOperation.Builder withValues(
            ContentProviderOperation.Builder b, JSONObject o) throws JSONException {
        return b.withValues(values(o));
    }

    /**
     * items: [{"raw": {starred, ...}, "data": [{mimetype, data1, data2, ...}]}]
     * One applyBatch: a raw contact (no account) and its data rows per item,
     * a yield point at every raw contact. Returns the raw contact ids.
     */
    private JSONObject contacts(JSONArray items) throws Exception {
        Uri raw = Uri.parse("content://com.android.contacts/raw_contacts");
        Uri data = Uri.parse("content://com.android.contacts/data");
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();
        List<Integer> rawIndex = new ArrayList<>();
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.getJSONObject(i);
            int back = ops.size();
            rawIndex.add(back);
            ContentValues rv = values(item.optJSONObject("raw") == null
                    ? new JSONObject() : item.getJSONObject("raw"));
            rv.putNull("account_type");
            rv.putNull("account_name");
            ops.add(ContentProviderOperation.newInsert(raw).withValues(rv)
                    .withYieldAllowed(true).build());
            JSONArray rows = item.optJSONArray("data");
            for (int j = 0; rows != null && j < rows.length(); j++) {
                ops.add(withValues(ContentProviderOperation.newInsert(data), rows.getJSONObject(j))
                        .withValueBackReference("raw_contact_id", back).build());
            }
        }
        ContentProviderResult[] res = applyBatch(CONTACTS, ops);
        JSONArray ids = new JSONArray();
        for (int idx : rawIndex) ids.put(idOf(res[idx].uri));
        return new JSONObject().put("ids", ids);
    }

    private static Uri syncAdapter(String base, String accountName, String accountType) {
        return Uri.parse(base).buildUpon()
                .appendQueryParameter("caller_is_syncadapter", "true")
                .appendQueryParameter("account_name", accountName)
                .appendQueryParameter("account_type", accountType)
                .build();
    }

    /**
     * {"account": {name, type}, "create": {calendar columns} | "calendar_id": n,
     *  "items": [{event columns}]}: creates OUR local calendar through the
     * sync-adapter URI (once), then inserts the events into it.
     */
    private JSONObject calendar(JSONObject req) throws Exception {
        JSONObject acct = req.getJSONObject("account");
        String name = acct.getString("name");
        String type = acct.getString("type");
        long calId = req.optLong("calendar_id", -1);
        if (calId < 0) {
            ContentValues cv = values(req.getJSONObject("create"));
            cv.put("account_name", name);
            cv.put("account_type", type);
            calId = idOf(insert(syncAdapter("content://com.android.calendar/calendars", name, type), cv));
            if (calId < 0) throw new IllegalStateException("calendar insert failed");
        }
        Uri events = syncAdapter("content://com.android.calendar/events", name, type);
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();
        JSONArray items = req.optJSONArray("items");
        for (int i = 0; items != null && i < items.length(); i++) {
            ContentValues cv = values(items.getJSONObject(i));
            cv.put("calendar_id", calId);
            ops.add(ContentProviderOperation.newInsert(events).withValues(cv)
                    .withYieldAllowed(true).build());
        }
        JSONArray ids = new JSONArray();
        if (!ops.isEmpty()) {
            for (ContentProviderResult r : applyBatch(CALENDAR, ops)) ids.put(idOf(r.uri));
        }
        return new JSONObject().put("calendar_id", calId).put("ids", ids);
    }

    /** items: [{call_log columns}]; one applyBatch. */
    private JSONObject calls(JSONArray items) throws Exception {
        Uri uri = Uri.parse("content://call_log/calls");
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();
        for (int i = 0; i < items.length(); i++) {
            ops.add(withValues(ContentProviderOperation.newInsert(uri), items.getJSONObject(i)).build());
        }
        JSONArray ids = new JSONArray();
        for (ContentProviderResult r : applyBatch(CALL_LOG, ops)) ids.put(idOf(r.uri));
        return new JSONObject().put("ids", ids);
    }

    private final Map<String, Long> threads = new HashMap<>();

    private long threadId(String address) throws Exception {
        Long known = threads.get(address);
        if (known != null) return known;
        Uri uri = Uri.parse("content://mms-sms/threadID").buildUpon()
                .appendQueryParameter("recipient", address).build();
        long id = -1;
        try (Cursor c = queryCursor(uri, new String[] {"_id"}, null, null, null)) {
            if (c != null && c.moveToFirst()) id = c.getLong(0);
        }
        if (id < 0) throw new IllegalStateException("no thread for " + address);
        threads.put(address, id);
        return id;
    }

    /**
     * items: [{address, body, date, date_sent, type (1 inbox, 2 sent), read,
     * seen}]. The thread id is looked up once per address, then the rows go in
     * one applyBatch (row by row when the provider refuses the batch).
     */
    private JSONObject sms(JSONArray items) throws Exception {
        Uri uri = Uri.parse("content://sms");
        List<ContentValues> rows = new ArrayList<>();
        ArrayList<ContentProviderOperation> ops = new ArrayList<>();
        for (int i = 0; i < items.length(); i++) {
            JSONObject o = items.getJSONObject(i);
            ContentValues cv = values(o);
            cv.put("thread_id", threadId(o.getString("address")));
            rows.add(cv);
            ops.add(ContentProviderOperation.newInsert(uri).withValues(cv).build());
        }
        long before = maxId("sms");
        JSONArray ids = new JSONArray();
        String mode = "batch";
        try {
            for (ContentProviderResult r : applyBatch(SMS, ops)) ids.put(idOf(r.uri));
        } catch (Throwable batchFailed) {
            // Part of the batch may be committed: take those rows' ids and
            // insert only the rows that are missing, never a second copy.
            mode = "recovered";
            Map<String, List<Long>> committed = new HashMap<>();
            try (Cursor c = queryCursor(uri, new String[] {"_id", "address", "date", "type", "body"},
                    "_id > ?", new String[] {String.valueOf(before)}, "_id")) {
                while (c != null && c.moveToNext()) {
                    String key = smsKey(c.getString(1), c.getLong(2), c.getLong(3), c.getString(4));
                    List<Long> l = committed.get(key);
                    if (l == null) committed.put(key, l = new ArrayList<>());
                    l.add(c.getLong(0));
                }
            }
            ids = new JSONArray();
            for (ContentValues cv : rows) {
                String key = smsKey(cv.getAsString("address"), cv.getAsLong("date"),
                        cv.getAsLong("type"), cv.getAsString("body"));
                List<Long> l = committed.get(key);
                ids.put(l != null && !l.isEmpty() ? l.remove(0) : idOf(insert(uri, cv)));
            }
        }
        return new JSONObject().put("ids", ids).put("mode", mode);
    }

    private static String smsKey(String address, Long date, Long type, String body) {
        return address + "\u0000" + date + "\u0000" + type + "\u0000" + body;
    }

    // ------------------------------------------------------------ sync state

    private static List<Account> accounts(JSONObject req) throws JSONException {
        List<Account> out = new ArrayList<>();
        JSONArray a = req.optJSONArray("accounts");
        for (int i = 0; a != null && i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            out.add(new Account(o.getString("name"), o.getString("type")));
        }
        return out;
    }

    private static List<String> authorities(JSONObject req) throws JSONException {
        List<String> out = new ArrayList<>();
        JSONArray a = req.optJSONArray("authorities");
        if (a == null) {
            out.add(CONTACTS);
            out.add(CALENDAR);
        }
        for (int i = 0; a != null && i < a.length(); i++) out.add(a.getString(i));
        return out;
    }

    private JSONObject syncState(JSONObject req) throws Exception {
        JSONArray rows = new JSONArray();
        for (Account acct : accounts(req)) {
            for (String auth : authorities(req)) {
                rows.put(new JSONObject()
                        .put("name", acct.name)
                        .put("type", acct.type)
                        .put("authority", auth)
                        .put("auto", ContentResolver.getSyncAutomatically(acct, auth))
                        .put("syncable", ContentResolver.getIsSyncable(acct, auth))
                        .put("active", ContentResolver.isSyncActive(acct, auth)));
            }
        }
        return new JSONObject()
                .put("master", ContentResolver.getMasterSyncAutomatically())
                .put("rows", rows);
    }

    /** setSyncAutomatically(false) and cancelSync for every account x authority. */
    private JSONObject syncOff(JSONObject req) throws Exception {
        for (Account acct : accounts(req)) {
            for (String auth : authorities(req)) {
                ContentResolver.setSyncAutomatically(acct, auth, false);
                ContentResolver.cancelSync(acct, auth);
            }
        }
        return syncState(req);
    }

    // ------------------------------------------------------ count / delete

    /** Ledger list -> [uri, extra selection] (rows of OUR seeding live there). */
    private static String[] table(String list) {
        switch (list) {
            case "contacts": return new String[] {"content://com.android.contacts/raw_contacts", "deleted=0"};
            case "calendars": return new String[] {"content://com.android.calendar/calendars", null};
            case "events": return new String[] {"content://com.android.calendar/events", "deleted=0"};
            case "calls": return new String[] {"content://call_log/calls", null};
            case "sms": return new String[] {"content://sms", null};
            case "images": return new String[] {"content://media/external/images/media", null};
            case "aggregates": return new String[] {"content://com.android.contacts/contacts", null};
            default: throw new IllegalArgumentException("unknown list " + list);
        }
    }

    private static String inClause(JSONArray ids) throws JSONException {
        StringBuilder sb = new StringBuilder("_id IN (");
        for (int i = 0; i < ids.length(); i++) {
            if (i > 0) sb.append(',');
            sb.append(ids.getLong(i));
        }
        return sb.append(')').toString();
    }

    private static String and(String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return "(" + a + ") AND (" + b + ")";
    }

    private int countRows(String uri, String selection) throws Exception {
        try (Cursor c = queryCursor(Uri.parse(uri), new String[] {"_id"}, selection, null, null)) {
            return c == null ? -1 : c.getCount();
        }
    }

    /**
     * {"lists": {name: [ids]}} counts which of those rows still exist;
     * {"totals": [names]} counts every row of those tables.
     */
    private JSONObject count(JSONObject req) throws Exception {
        JSONObject result = new JSONObject();
        JSONObject lists = req.optJSONObject("lists");
        if (lists != null) {
            JSONObject counts = new JSONObject();
            Iterator<String> it = lists.keys();
            while (it.hasNext()) {
                String name = it.next();
                JSONArray ids = lists.getJSONArray(name);
                String[] t = table(name);
                counts.put(name, ids.length() == 0 ? 0 : countRows(t[0], and(t[1], inClause(ids))));
            }
            result.put("counts", counts);
        }
        JSONArray totals = req.optJSONArray("totals");
        if (totals != null) {
            JSONObject counts = new JSONObject();
            for (int i = 0; i < totals.length(); i++) {
                String name = totals.getString(i);
                String[] t = table(name);
                try {
                    counts.put(name, countRows(t[0], t[1]));
                } catch (Throwable e) {
                    counts.put(name, -1);
                }
            }
            result.put("totals", counts);
        }
        return result;
    }

    /**
     * {"lists": {name: [ids]}, "account": {name, type}}: deletes those rows.
     * Contacts and calendar rows are deleted as their sync adapter, so they
     * are gone at once instead of being marked deleted.
     */
    private JSONObject delete(JSONObject req) throws Exception {
        JSONObject lists = req.getJSONObject("lists");
        JSONObject acct = req.optJSONObject("account");
        JSONObject deleted = new JSONObject();
        Iterator<String> it = lists.keys();
        while (it.hasNext()) {
            String name = it.next();
            JSONArray ids = lists.getJSONArray(name);
            if (ids.length() == 0) {
                deleted.put(name, 0);
                continue;
            }
            String base = table(name)[0];
            Uri uri;
            String guard = null;
            if ("contacts".equals(name)) {
                uri = Uri.parse(base).buildUpon()
                        .appendQueryParameter("caller_is_syncadapter", "true").build();
                guard = NO_ACCOUNT;  // never a row of an account (Google)
            } else if (("events".equals(name) || "calendars".equals(name)) && acct != null) {
                uri = syncAdapter(base, acct.getString("name"), acct.getString("type"));
            } else {
                uri = Uri.parse(base);
            }
            deleted.put(name, deleteRows(uri, and(inClause(ids), guard), null));
        }
        return new JSONObject().put("deleted", deleted);
    }

    static final String NO_ACCOUNT = "account_type IS NULL AND account_name IS NULL";

    /** Highest _id of a table, deleted rows included (0 when empty). */
    private long maxId(String list) throws Exception {
        String uri;
        switch (list) {
            case "contacts": uri = "content://com.android.contacts/raw_contacts"; break;
            case "events": uri = "content://com.android.calendar/events"; break;
            default: uri = table(list)[0];
        }
        try (Cursor c = queryCursor(Uri.parse(uri), new String[] {"_id"}, null, null, "_id DESC")) {
            return c != null && c.moveToFirst() ? c.getLong(0) : 0;
        }
    }

    /** {"tables": [contacts, calendars, events, calls, sms]} -> {"max": {name: id}}. */
    private JSONObject maxIds(JSONObject req) throws Exception {
        JSONArray tables = req.getJSONArray("tables");
        JSONObject max = new JSONObject();
        for (int i = 0; i < tables.length(); i++) {
            max.put(tables.getString(i), maxId(tables.getString(i)));
        }
        return new JSONObject().put("max", max);
    }

    /**
     * {"max": {name: id}, "account": {name, type}}: deletes the rows a killed
     * run made after preflight that the ledger never heard of (the device was
     * offline with sync off, so new rows there are ours). Fixed guards: only
     * account-less raw contacts; calls; SMS; events and calendars of OUR
     * LOCAL calendar account only. Rows of the Google account are never hit.
     */
    private JSONObject deleteAbove(JSONObject req) throws Exception {
        JSONObject max = req.getJSONObject("max");
        JSONObject acct = req.optJSONObject("account");
        JSONObject deleted = new JSONObject();
        Iterator<String> it = max.keys();
        while (it.hasNext()) {
            String name = it.next();
            String above = String.valueOf(max.getLong(name));
            switch (name) {
                case "contacts":
                    deleted.put(name, deleteRows(Uri.parse("content://com.android.contacts/raw_contacts")
                            .buildUpon().appendQueryParameter("caller_is_syncadapter", "true").build(),
                            "_id > ? AND " + NO_ACCOUNT, new String[] {above}));
                    break;
                case "calls":
                case "sms":
                    deleted.put(name, deleteRows(Uri.parse(table(name)[0]), "_id > ?", new String[] {above}));
                    break;
                case "events":
                case "calendars": {
                    if (acct == null || !"LOCAL".equals(acct.optString("type"))) {
                        deleted.put(name, 0);  // only our LOCAL calendar account
                        break;
                    }
                    String an = acct.getString("name");
                    String sel = "events".equals(name)
                            ? "_id > ? AND calendar_id IN (SELECT _id FROM Calendars"
                                    + " WHERE account_type='LOCAL' AND account_name=?)"
                            : "_id > ? AND account_type='LOCAL' AND account_name=?";
                    deleted.put(name, deleteRows(syncAdapter(table(name)[0], an, "LOCAL"),
                            sel, new String[] {above, an}));
                    break;
                }
                default:
                    throw new IllegalArgumentException("no delete_above for " + name);
            }
        }
        return new JSONObject().put("deleted", deleted);
    }

    /** {"uri", "projection", "selection", "args", "sort"} -> {"rows": [...]}. */
    private JSONObject query(JSONObject req) throws Exception {
        JSONArray p = req.optJSONArray("projection");
        String[] projection = null;
        if (p != null) {
            projection = new String[p.length()];
            for (int i = 0; i < p.length(); i++) projection[i] = p.getString(i);
        }
        JSONArray a = req.optJSONArray("args");
        String[] args = null;
        if (a != null) {
            args = new String[a.length()];
            for (int i = 0; i < a.length(); i++) args[i] = a.getString(i);
        }
        JSONArray rows = new JSONArray();
        try (Cursor c = queryCursor(Uri.parse(req.getString("uri")), projection,
                req.has("selection") ? req.getString("selection") : null, args,
                req.has("sort") ? req.getString("sort") : null)) {
            while (c != null && c.moveToNext()) {
                JSONObject row = new JSONObject();
                for (int i = 0; i < c.getColumnCount(); i++) {
                    String col = c.getColumnName(i);
                    switch (c.getType(i)) {
                        case Cursor.FIELD_TYPE_NULL: row.put(col, JSONObject.NULL); break;
                        case Cursor.FIELD_TYPE_INTEGER: row.put(col, c.getLong(i)); break;
                        case Cursor.FIELD_TYPE_FLOAT: row.put(col, c.getDouble(i)); break;
                        case Cursor.FIELD_TYPE_BLOB: row.put(col, "<blob>"); break;
                        default: row.put(col, c.getString(i));
                    }
                }
                rows.put(row);
            }
        }
        return new JSONObject().put("rows", rows);
    }
}
