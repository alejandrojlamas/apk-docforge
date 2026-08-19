from __future__ import annotations

from apk_docforge.tools.manifest_parser import parse_manifest_bytes


def test_manifest_xml_to_json() -> None:
    xml = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.example" android:versionName="1" android:versionCode="2">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:label="Example" android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>"""
    parsed = parse_manifest_bytes(xml)
    assert parsed.parser == "xml"
    assert parsed.manifest["package_name"] == "com.example"
    assert parsed.manifest["version_name"] == "1"
    assert parsed.manifest["min_sdk"] == "23"
    assert parsed.manifest["permissions"][0]["name"] == "android.permission.INTERNET"
    assert parsed.manifest["components"]["activities"][0]["name"] == ".MainActivity"
