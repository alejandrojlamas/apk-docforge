from __future__ import annotations

import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from apk_docforge.config import get_settings
from apk_docforge.db.session import reset_engine


@pytest.fixture
def isolated_app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("APK_DOCFORGE_DB_URL", f"sqlite:///{tmp_path / 'apk_docforge.db'}")
    monkeypatch.setenv("APK_DOCFORGE_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("APK_DOCFORGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("APK_DOCFORGE_OFFICIAL_URL_ALLOWLIST", "example.com,downloads.example.org")
    monkeypatch.setenv("APK_DOCFORGE_LOCAL_ENV_PATH", str(tmp_path / ".env"))
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("APK_DOCFORGE_DEEPSEEK_API_KEY", raising=False)
    get_settings.cache_clear()
    reset_engine()
    yield tmp_path
    reset_engine()
    get_settings.cache_clear()
    monkeypatch.delenv("APK_DOCFORGE_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("APK_DOCFORGE_GOOGLE_PLAY_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("APK_DOCFORGE_ALLOW_DYNAMIC", raising=False)


@pytest.fixture
def sample_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "sample.apk"
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.sample"
    android:versionName="1.2.3"
    android:versionCode="123">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.CAMERA" />
  <application
      android:label="Sample App"
      android:allowBackup="true"
      android:debuggable="false"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="sample" android:host="open" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"""
    strings = """<resources>
  <string name="app_name">Sample App</string>
  <string name="login">Login</string>
  <string name="pay">Pay now</string>
</resources>
"""
    layout = """<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">
  <Button android:id="@+id/login_button" android:text="@string/login" />
  <Button android:id="@+id/pay_button" android:text="@string/pay" />
  <EditText android:id="@+id/email" android:hint="Email" />
</LinearLayout>
"""
    dex = (
        b"Lcom/example/sample/MainActivity; "
        b"https://api.example.com/v1/login "
        b"okhttp3 Retrofit firebase crashlytics WebView sharedpreferences "
        b"CertificatePinner BillingClient LicenseChecker isDebuggerConnected"
    )
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", dex)
        archive.writestr("res/values/strings.xml", strings)
        archive.writestr("res/layout/activity_main.xml", layout)
    return apk
