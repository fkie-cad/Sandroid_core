"""Tests for sandroid.services.component_info_parser.

Bug-fix context: ``parse_component_info`` used to scan `dumpsys package
<pkg>` text for ``Activity #0:``/``exported=``/``permission=`` blocks. Three
independent verification passes confirmed that data doesn't exist in real
`dumpsys package` output at all (live-tested against WhatsApp/Chrome on a
real emulator: empty component lists both times -- a silent false negative
-- and cross-checked against AOSP's ``Settings.java::dumpComponents()``
across three Android versions). The function now parses the app's real,
decoded ``AndroidManifest.xml`` instead (see the module docstring in
``sandroid/services/component_info_parser.py`` for the full story).

``COMPONENT_MANIFEST_FIXTURE`` below is assembled from real captured
``<activity>``/``<service>``/``<receiver>``/``<provider>`` XML elements --
byte-for-byte copies of what ``androguard.core.apk.APK.get_android_manifest_xml()``
produced for real installed apps on a live emulator (WhatsApp, package
``com.whatsapp``; Microsoft Edge, package ``com.microsoft.emmx``, for the
one multi-authority provider, since no on-device WhatsApp provider happened
to declare more than one authority). Real ``targetSdkVersion`` for both is
36. Every test below documents which real component it came from.

``DUMPSYS_PACKAGE_FIXTURE`` (for ``parse_extended_package_info``, which was
separately confirmed correct and is unchanged) is a trimmed-but-real capture
of ``adb shell dumpsys package com.whatsapp``'s ``Packages:`` section from
that same emulator -- including the real structural detail that `dataDir=`/
`firstInstallTime=` sit nested under a `User 0:` sub-block on modern
(API 36) Android, not at the top `Package [...]:` level like the old
hand-built fixture assumed (harmless for the parser, which does an
unanchored regex search either way, but worth getting right in the fixture).
"""

from sandroid.services.component_info_parser import (
    merge_component_info,
    parse_component_info,
    parse_extended_package_info,
)

# Real targetSdkVersion for both source apps (WhatsApp, Microsoft Edge) at
# capture time.
_REAL_TARGET_SDK = 36

# Real decoded-manifest snippets, assembled into one document. Each
# component block below is copied verbatim (whitespace aside) from
# `etree.tostring(APK(<real apk pulled from a live emulator>).get_android_manifest_xml())`.
COMPONENT_MANIFEST_FIXTURE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.whatsapp">
  <application>
    <!-- real: com.whatsapp.home.ui.HomeActivity - exported=true, no
         permission, four distinct real <intent-filter> blocks (NDEF
         discovery, two custom-scheme deep links, and an autoVerify
         https App Link). -->
    <activity android:theme="@7F1504C6" android:name="com.whatsapp.home.ui.HomeActivity" android:exported="true" android:launchMode="2" android:configChanges="0x00000DB0">
      <intent-filter android:label="@7F124C11">
        <action android:name="android.nfc.action.NDEF_DISCOVERED"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:mimeType="application/com.whatsapp.chat"/>
        <data android:mimeType="application/com.whatsapp.join"/>
      </intent-filter>
      <intent-filter android:label="@7F124C11">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="whatsapp" android:host="chat"/>
      </intent-filter>
      <intent-filter android:label="@7F124C11">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="whatsapp" android:host="call"/>
      </intent-filter>
      <intent-filter android:label="@7F124C11" android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:host="call.whatsapp.com"/>
      </intent-filter>
    </activity>

    <!-- real: com.whatsapp.pixel.besties.activity.PixelBestiesUpsellActivity
         - exported=true, guarded by a real permission, two real
         <intent-filter> blocks with no <data>. -->
    <activity android:name="com.whatsapp.pixel.besties.activity.PixelBestiesUpsellActivity" android:permission="com.google.permission.besties.API" android:exported="true">
      <intent-filter>
        <action android:name="com.whatsapp.pixel.besties.ACTION_CHAT"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
      <intent-filter>
        <action android:name="com.whatsapp.pixel.besties.ACTION_INVITE"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
    </activity>

    <!-- real: com.whatsapp.accountdelete.account.delete.DeleteAccountActivity
         - no explicit android:exported *and* no intent-filter, so this
         exercises the real implicit-default path (exported defaults to
         False with no intent-filter), not an explicit exported="false". -->
    <activity android:theme="@7F1504AE" android:name="com.whatsapp.accountdelete.account.delete.DeleteAccountActivity" android:configChanges="0x00000FB0" android:windowSoftInputMode="0x00000001"/>

    <!-- real: androidx.sharetarget.ChooserTargetServiceCompat - exported
         service guarded by a permission, with one real intent-filter. -->
    <service android:name="androidx.sharetarget.ChooserTargetServiceCompat" android:permission="android.permission.BIND_CHOOSER_TARGET_SERVICE" android:exported="true">
      <intent-filter>
        <action android:name="android.service.chooser.ChooserTargetService"/>
      </intent-filter>
    </service>

    <!-- real: com.whatsapp.alarmservice.AlarmService - explicitly
         non-exported (also permission-guarded, but that's moot since it's
         not exported either way). -->
    <service android:name="com.whatsapp.alarmservice.AlarmService" android:permission="android.permission.BIND_JOB_SERVICE" android:exported="false"/>

    <!-- real: com.google.firebase.iid.FirebaseInstanceIdReceiver - exported
         receiver guarded by a permission, one intent-filter, plus a
         <meta-data> child the parser should simply ignore. -->
    <receiver android:name="com.google.firebase.iid.FirebaseInstanceIdReceiver" android:permission="com.google.android.c2dm.permission.SEND" android:exported="true">
      <intent-filter>
        <action android:name="com.google.android.c2dm.intent.RECEIVE"/>
      </intent-filter>
      <meta-data android:name="com.google.android.gms.cloudmessaging.FINISHED_AFTER_HANDLED" android:value="true"/>
    </receiver>

    <!-- real: com.whatsapp.calling.calllink.CallLinkShareReceiver -
         explicitly non-exported, no intent-filter. -->
    <receiver android:name="com.whatsapp.calling.calllink.CallLinkShareReceiver" android:exported="false"/>

    <!-- real: androidx.car.app.connection.provider - no explicit
         android:exported at all, exercising the provider implicit-default
         path (False, since real targetSdkVersion 36 >= 17). -->
    <provider android:name="androidx.car.app.connection.provider" android:authorities="androidx.car.app.connection"/>

    <!-- real: com.whatsapp.backup.google.restart.RestartAppContentProvider
         - explicitly non-exported, no read/write permission. -->
    <provider android:name="com.whatsapp.backup.google.restart.RestartAppContentProvider" android:enabled="true" android:exported="false" android:authorities="com.whatsapp.backup.google.restart.RestartAppContentProvider"/>

    <!-- real: com.whatsapp.orbitsso.OrbitSsoProvider - exported, guarded by
         a real readPermission with no writePermission set. -->
    <provider android:name="com.whatsapp.orbitsso.OrbitSsoProvider" android:readPermission="com.whatsapp.orbit.permission.SSO" android:enabled="true" android:exported="true" android:authorities="com.whatsapp.orbitsso"/>

    <!-- real: org.chromium.chrome.browser.provider.ChromeBrowserProvider
         (from Microsoft Edge, com.microsoft.emmx) - the one real
         multi-authority provider found across both captured apps; also has
         a <path-permission> child, out of scope for this parser (same as
         the blanket android:permission being folded into read/write but a
         per-path override is not). -->
    <provider android:name="org.chromium.chrome.browser.provider.ChromeBrowserProvider" android:exported="true" android:authorities="com.microsoft.emmx.ChromeBrowserProvider;com.microsoft.emmx.browser;com.microsoft.emmx">
      <path-permission android:readPermission="android.permission.GLOBAL_SEARCH" android:path="/bookmarks/search_suggest_query"/>
    </provider>
  </application>
</manifest>
"""


# -- parse_component_info: activities ---------------------------------------


def test_exported_activity_with_no_permission_and_multiple_intent_filters():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    home_activity = next(
        a
        for a in result["components"]["activities"]
        if a["name"] == "com.whatsapp.home.ui.HomeActivity"
    )

    assert home_activity["exported"] is True
    assert home_activity["permission"] is None
    assert len(home_activity["intent_filters"]) == 4


def test_exported_activity_with_guarding_permission():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    besties_activity = next(
        a
        for a in result["components"]["activities"]
        if a["name"] == "com.whatsapp.pixel.besties.activity.PixelBestiesUpsellActivity"
    )

    assert besties_activity["exported"] is True
    assert besties_activity["permission"] == "com.google.permission.besties.API"
    assert len(besties_activity["intent_filters"]) == 2
    assert besties_activity["intent_filters"][0]["actions"] == [
        "com.whatsapp.pixel.besties.ACTION_CHAT"
    ]
    assert besties_activity["intent_filters"][0]["data"] == []


def test_non_exported_activity_via_implicit_default():
    """No explicit android:exported and no intent-filter -> defaults False."""
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    delete_account_activity = next(
        a
        for a in result["components"]["activities"]
        if a["name"]
        == "com.whatsapp.accountdelete.account.delete.DeleteAccountActivity"
    )

    assert delete_account_activity["exported"] is False
    assert delete_account_activity["permission"] is None
    assert delete_account_activity["intent_filters"] == []


def test_intent_filter_actions_and_categories_captured():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    home_activity = next(
        a
        for a in result["components"]["activities"]
        if a["name"] == "com.whatsapp.home.ui.HomeActivity"
    )

    view_filters = [
        f
        for f in home_activity["intent_filters"]
        if "android.intent.action.VIEW" in f["actions"]
    ]
    assert len(view_filters) == 3
    for filt in view_filters:
        assert "android.intent.category.BROWSABLE" in filt["categories"]
        assert "android.intent.category.DEFAULT" in filt["categories"]


def test_intent_filter_data_entries_captured_per_real_data_tag():
    """Each real <data> tag becomes its own dict; multi-attribute <data>
    tags (scheme+host together) keep both attributes on one entry, matching
    how the real manifest actually groups them."""
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    home_activity = next(
        a
        for a in result["components"]["activities"]
        if a["name"] == "com.whatsapp.home.ui.HomeActivity"
    )

    chat_filter = next(
        f
        for f in home_activity["intent_filters"]
        if f["data"] and f["data"][0].get("host") == "chat"
    )
    assert chat_filter["data"] == [{"scheme": "whatsapp", "host": "chat"}]

    https_filter = next(
        f
        for f in home_activity["intent_filters"]
        if any(d.get("scheme") == "https" for d in f["data"])
    )
    assert {"scheme": "http"} in https_filter["data"]
    assert {"scheme": "https"} in https_filter["data"]
    assert {"host": "call.whatsapp.com"} in https_filter["data"]


# -- parse_component_info: services / receivers -----------------------------


def test_exported_service_with_permission_and_filter():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    chooser_service = next(
        s
        for s in result["components"]["services"]
        if s["name"] == "androidx.sharetarget.ChooserTargetServiceCompat"
    )

    assert chooser_service["exported"] is True
    assert (
        chooser_service["permission"]
        == "android.permission.BIND_CHOOSER_TARGET_SERVICE"
    )
    assert chooser_service["intent_filters"][0]["actions"] == [
        "android.service.chooser.ChooserTargetService"
    ]


def test_non_exported_service_marked_correctly():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    alarm_service = next(
        s
        for s in result["components"]["services"]
        if s["name"] == "com.whatsapp.alarmservice.AlarmService"
    )

    assert alarm_service["exported"] is False


def test_exported_receiver_with_permission_and_filter():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    firebase_receiver = next(
        r
        for r in result["components"]["receivers"]
        if r["name"] == "com.google.firebase.iid.FirebaseInstanceIdReceiver"
    )

    assert firebase_receiver["exported"] is True
    assert firebase_receiver["permission"] == "com.google.android.c2dm.permission.SEND"
    assert firebase_receiver["intent_filters"][0]["actions"] == [
        "com.google.android.c2dm.intent.RECEIVE"
    ]


def test_non_exported_receiver_marked_correctly():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    call_link_receiver = next(
        r
        for r in result["components"]["receivers"]
        if r["name"] == "com.whatsapp.calling.calllink.CallLinkShareReceiver"
    )

    assert call_link_receiver["exported"] is False


# -- parse_component_info: providers -----------------------------------------


def test_provider_with_no_explicit_exported_defaults_false_on_modern_target_sdk():
    """androidx.car.app.connection.provider declares no android:exported at
    all; real targetSdkVersion 36 >= 17 so the implicit default is False."""
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    car_provider = next(
        p
        for p in result["components"]["providers"]
        if p["name"] == "androidx.car.app.connection.provider"
    )

    assert car_provider["exported"] is False
    assert car_provider["read_permission"] is None
    assert car_provider["write_permission"] is None
    assert car_provider["authorities"] == ["androidx.car.app.connection"]


def test_provider_with_no_explicit_exported_defaults_true_below_sdk_17():
    """Documents the legacy (pre-Android-4.2) provider default rule, which
    cannot be observed on any real modern device -- verified against the
    Android platform docs / AOSP PackageParser default-computation instead
    of a live capture, unlike every other case in this file."""
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, target_sdk=16)
    car_provider = next(
        p
        for p in result["components"]["providers"]
        if p["name"] == "androidx.car.app.connection.provider"
    )

    assert car_provider["exported"] is True


def test_non_exported_provider_has_no_permissions():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    restart_provider = next(
        p
        for p in result["components"]["providers"]
        if p["name"] == "com.whatsapp.backup.google.restart.RestartAppContentProvider"
    )

    assert restart_provider["exported"] is False
    assert restart_provider["read_permission"] is None
    assert restart_provider["write_permission"] is None


def test_exported_provider_guarded_by_read_permission_only():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    orbit_provider = next(
        p
        for p in result["components"]["providers"]
        if p["name"] == "com.whatsapp.orbitsso.OrbitSsoProvider"
    )

    assert orbit_provider["exported"] is True
    assert orbit_provider["read_permission"] == "com.whatsapp.orbit.permission.SSO"
    assert orbit_provider["write_permission"] is None
    assert orbit_provider["authorities"] == ["com.whatsapp.orbitsso"]


def test_provider_with_multiple_authorities_returns_a_list():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    chrome_provider = next(
        p
        for p in result["components"]["providers"]
        if p["name"] == "org.chromium.chrome.browser.provider.ChromeBrowserProvider"
    )

    assert chrome_provider["exported"] is True
    assert chrome_provider["authorities"] == [
        "com.microsoft.emmx.ChromeBrowserProvider",
        "com.microsoft.emmx.browser",
        "com.microsoft.emmx",
    ]


def test_component_counts_match_fixture():
    result = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)

    assert len(result["components"]["activities"]) == 3
    assert len(result["components"]["services"]) == 2
    assert len(result["components"]["receivers"]) == 2
    assert len(result["components"]["providers"]) == 4


# -- merge_component_info -----------------------------------------------------


def test_merge_component_info_dedupes_by_name_keeping_first_occurrence():
    base = parse_component_info(COMPONENT_MANIFEST_FIXTURE, _REAL_TARGET_SDK)
    # A second "split" that repeats one real activity (should be ignored,
    # first wins) and contributes nothing new.
    split_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.whatsapp">
  <application>
    <activity android:name="com.whatsapp.home.ui.HomeActivity" android:exported="false"/>
  </application>
</manifest>
"""
    split = parse_component_info(split_manifest, _REAL_TARGET_SDK)

    merged = merge_component_info([base, split])

    assert len(merged["components"]["activities"]) == 3
    home_activity = next(
        a
        for a in merged["components"]["activities"]
        if a["name"] == "com.whatsapp.home.ui.HomeActivity"
    )
    # base.apk's entry (exported=True) wins, not the split's exported=False.
    assert home_activity["exported"] is True


def test_merge_component_info_empty_list_yields_empty_components():
    merged = merge_component_info([])

    assert merged == {
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
    }


# -- parse_extended_package_info ---------------------------------------------

# Real (trimmed) capture of `adb shell dumpsys package com.whatsapp`'s
# `Packages:` section from a live emulator (API 36). Trimmed of several
# real but bulky/irrelevant fields (queriesPackages, queriesIntents, most of
# the ~40-entry requested-permissions list, native lib paths) for
# readability; every field this parser reads is untouched and genuine,
# including the real structural detail that `dataDir=`/`firstInstallTime=`
# live under `User 0:`, not at the top `Package [...]:` level.
DUMPSYS_PACKAGE_FIXTURE = """
Packages:
  Package [com.whatsapp] (a8d3b50):
    appId=10224
    pkg=Package{614d149 com.whatsapp}
    codePath=/data/app/~~tZaK9qfh5oMomQEx9xr-IQ==/com.whatsapp-Kh7Fy2-_FSfhEOgxcgHCdA==
    versionCode=262707030 minSdk=21 targetSdk=36
    versionName=2.26.27.70
    splits=[base]
    apkSigningVersion=3
    timeStamp=2026-07-09 23:44:25
    lastUpdateTime=2026-07-09 23:44:28
    installerPackageName=com.google.android.packageinstaller
    installerPackageUid=10105
    signatures=PackageSignatures{6178a4e version:3, signatures:[d5acdcd2], past signatures:[2b6cb416 flags: 1f, d5acdcd2 flags: 17]}
    declared permissions:
      com.whatsapp.orbit.permission.SSO: prot=signature
      com.whatsapp.permission.BROADCAST: prot=signature
    requested permissions:
      android.permission.FOREGROUND_SERVICE_CAMERA
      com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
      android.permission.POST_NOTIFICATIONS
      android.permission.READ_CALL_LOG
      android.permission.ACCESS_FINE_LOCATION
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=1032698 deDataInode=803719 installed=true hidden=false suspended=false stopped=false
      dataDir=/data/user/0/com.whatsapp
      firstInstallTime=2026-07-09 23:40:54
"""


def test_uid_extracted_from_app_id_field():
    result = parse_extended_package_info(DUMPSYS_PACKAGE_FIXTURE)

    assert result["uid"] == 10224


def test_install_source_extracted_from_installer_package_name():
    result = parse_extended_package_info(DUMPSYS_PACKAGE_FIXTURE)

    assert result["install_source"] == "com.google.android.packageinstaller"


def test_install_source_is_none_when_installer_package_name_is_null():
    sideloaded = DUMPSYS_PACKAGE_FIXTURE.replace(
        "installerPackageName=com.google.android.packageinstaller",
        "installerPackageName=null",
    )

    result = parse_extended_package_info(sideloaded)

    assert result["install_source"] is None


def test_signing_info_extracted_when_present():
    result = parse_extended_package_info(DUMPSYS_PACKAGE_FIXTURE)

    assert result["signing_info"] == (
        "6178a4e version:3, signatures:[d5acdcd2], "
        "past signatures:[2b6cb416 flags: 1f, d5acdcd2 flags: 17]"
    )


def test_signing_info_is_none_when_signatures_line_absent():
    no_signatures = DUMPSYS_PACKAGE_FIXTURE.replace(
        "signatures=PackageSignatures{6178a4e version:3, signatures:[d5acdcd2], "
        "past signatures:[2b6cb416 flags: 1f, d5acdcd2 flags: 17]}\n",
        "",
    )

    result = parse_extended_package_info(no_signatures)

    assert result["signing_info"] is None


def test_requested_permissions_returns_multiple_entries_not_just_the_first():
    result = parse_extended_package_info(DUMPSYS_PACKAGE_FIXTURE)

    assert result["requested_permissions"] == [
        "android.permission.FOREGROUND_SERVICE_CAMERA",
        "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.READ_CALL_LOG",
        "android.permission.ACCESS_FINE_LOCATION",
    ]


def test_extended_info_still_includes_base_package_info_parser_fields():
    result = parse_extended_package_info(DUMPSYS_PACKAGE_FIXTURE)

    assert result["version_name"] == "2.26.27.70"
    assert result["version_code"] == 262707030
    assert result["target_sdk"] == 36
    assert result["min_sdk"] == 21
    assert result["data_dir"] == "/data/user/0/com.whatsapp"
    assert result["install_date"] == "2026-07-09 23:40:54"
