// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

const VINTF_MANIFEST_DIRS: &[&str] = &[
    "/system/etc/vintf/manifest",
    "/system_ext/etc/vintf/manifest",
    "/product/etc/vintf/manifest",
    "/vendor/etc/vintf/manifest",
    "/odm/etc/vintf/manifest",
];
const VINTF_MANIFEST_FILES: &[&str] = &[
    "/system/etc/vintf/manifest.xml",
    "/system_ext/etc/vintf/manifest.xml",
    "/product/etc/vintf/manifest.xml",
    "/vendor/etc/vintf/manifest.xml",
    "/odm/etc/vintf/manifest.xml",
];

#[derive(Debug, Deserialize)]
struct ManifestXml {
    #[serde(rename = "hal", default)]
    hals: Vec<HalXml>,
}

#[derive(Debug, Deserialize)]
struct HalXml {
    #[serde(rename = "@format")]
    format: Option<String>,
    name: Option<String>,
    #[serde(rename = "version", default)]
    versions: Vec<String>,
    #[serde(rename = "fqname", default)]
    fqnames: Vec<String>,
    #[serde(rename = "interface", default)]
    interfaces: Vec<InterfaceXml>,
}

#[derive(Debug, Deserialize)]
struct InterfaceXml {
    name: Option<String>,
    #[serde(rename = "instance", default)]
    instances: Vec<String>,
}

pub fn manifest_paths() -> Vec<PathBuf> {
    let mut paths = VINTF_MANIFEST_DIRS
        .iter()
        .filter_map(|directory| std::fs::read_dir(directory).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("xml"))
        .collect::<Vec<_>>();
    paths.extend(VINTF_MANIFEST_FILES.iter().map(PathBuf::from));
    paths
}

/// AOSP VINTF default for an AIDL HAL whose `<version>` is omitted.
pub const AIDL_OMITTED_VERSION: i32 = 1;

pub fn parse_aidl_hal_version_xml(
    xml: &str,
    hal_name: &str,
    interface: &str,
    instance: &str,
    normalize: impl Fn(i32) -> Option<i32>,
) -> Result<Option<i32>> {
    let manifest: ManifestXml =
        quick_xml::de::from_str(xml).context("failed to deserialize VINTF XML")?;
    for hal in manifest.hals {
        if !hal.references_aidl_instance(hal_name, interface, instance) {
            continue;
        }

        for version in hal.versions {
            let version = version
                .trim()
                .parse::<i32>()
                .with_context(|| format!("invalid VINTF version {version:?}"))?;
            if let Some(version) = normalize(version) {
                return Ok(Some(version));
            }
        }
    }

    Ok(None)
}

/// Resolve an AIDL HAL version from VINTF manifest texts.
///
/// Explicit usable versions across the scanned texts win. A matching instance
/// with no usable `<version>` is [`AIDL_OMITTED_VERSION`]. Absence of a matching
/// instance is `None`. Unrelated HALs and malformed XML are ignored.
pub fn resolve_aidl_hal_version_xmls<'a>(
    xmls: impl IntoIterator<Item = &'a str>,
    hal_name: &str,
    interface: &str,
    instance: &str,
    normalize: impl Fn(i32) -> Option<i32>,
) -> Option<i32> {
    let mut declared = false;
    let mut explicit = None;
    for xml in xmls {
        match parse_aidl_hal_version_xml(xml, hal_name, interface, instance, &normalize) {
            Ok(Some(version)) if explicit.is_none() => explicit = Some(version),
            Ok(_) => {}
            Err(_) => {}
        }
        if let Ok(true) = parse_aidl_hal_instance_xml(xml, hal_name, interface, instance) {
            declared = true;
        }
    }

    if let Some(version) = explicit {
        Some(version)
    } else if declared {
        normalize(AIDL_OMITTED_VERSION)
    } else {
        None
    }
}

pub fn parse_aidl_hal_instance_xml(
    xml: &str,
    hal_name: &str,
    interface: &str,
    instance: &str,
) -> Result<bool> {
    let manifest: ManifestXml =
        quick_xml::de::from_str(xml).context("failed to deserialize VINTF XML")?;
    Ok(manifest
        .hals
        .iter()
        .any(|hal| hal.references_aidl_instance(hal_name, interface, instance)))
}

impl HalXml {
    fn references_aidl_instance(&self, hal_name: &str, interface: &str, instance: &str) -> bool {
        self.format
            .as_deref()
            .is_some_and(|format| format.trim() == "aidl")
            && self.name.as_deref().map(str::trim) == Some(hal_name)
            && self.references_instance(interface, instance)
    }

    fn references_instance(&self, interface: &str, instance: &str) -> bool {
        let fqname = format!("{interface}/{instance}");
        self.fqnames
            .iter()
            .any(|candidate| candidate.trim() == fqname)
            || self.interfaces.iter().any(|candidate| {
                candidate.name.as_deref().map(str::trim) == Some(interface)
                    && candidate
                        .instances
                        .iter()
                        .any(|candidate| candidate.trim() == instance)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYMINT_HAL_NAME: &str = "android.hardware.security.keymint";
    const KEYMINT_DEVICE_INTERFACE: &str = "IKeyMintDevice";
    const KEYSTORE2_HAL_NAME: &str = "android.system.keystore2";
    const KEYSTORE2_SERVICE_INTERFACE: &str = "IKeystoreService";

    fn normalize_keymint_test_version(version: i32) -> Option<i32> {
        match version {
            1..=5 => Some(version * 100),
            100 | 200 | 300 | 400 | 500 => Some(version),
            _ => None,
        }
    }

    fn normalize_keystore2_test_version(version: i32) -> Option<i32> {
        (1..=5).contains(&version).then_some(version)
    }

    #[test]
    fn parser_matches_fqname_and_interface_forms() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>3</version>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_aidl_hal_version_xml(
                xml,
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            )
            .unwrap(),
            Some(400)
        );
        assert_eq!(
            parse_aidl_hal_version_xml(
                xml,
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "strongbox",
                normalize_keymint_test_version,
            )
            .unwrap(),
            Some(300)
        );
        assert!(parse_aidl_hal_instance_xml(
            xml,
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "default",
        )
        .unwrap());
        assert!(parse_aidl_hal_instance_xml(
            xml,
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "strongbox",
        )
        .unwrap());
        assert!(!parse_aidl_hal_instance_xml(
            xml,
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "foo",
        )
        .unwrap());
    }

    #[test]
    fn instance_parser_does_not_require_version() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert!(parse_aidl_hal_instance_xml(
            xml,
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "strongbox",
        )
        .unwrap());
    }

    #[test]
    fn parser_ignores_unrelated_hals_and_rejects_malformed_xml() {
        let unrelated = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.foo</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_aidl_hal_version_xml(
                unrelated,
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            )
            .unwrap(),
            None
        );
        assert!(parse_aidl_hal_version_xml(
            "<manifest>",
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "default",
            normalize_keymint_test_version,
        )
        .is_err());
    }

    #[test]
    fn unsupported_versions_are_ignored() {
        let xml = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.system.keystore2</name>
        <version>99</version>
        <fqname>IKeystoreService/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_aidl_hal_version_xml(
                xml,
                KEYSTORE2_HAL_NAME,
                KEYSTORE2_SERVICE_INTERFACE,
                "default",
                normalize_keystore2_test_version,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn omitted_aidl_version_on_declared_instance_is_effective_v1() {
        let qti_default = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IKeyMintDevice/default</fqname>
        <fqname>IRemotelyProvisionedComponent/default</fqname>
    </hal>
</manifest>
"#;
        let qti_strongbox = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_aidl_hal_version_xml(
                qti_default,
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [qti_default],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(AIDL_OMITTED_VERSION)
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [qti_strongbox],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "strongbox",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(AIDL_OMITTED_VERSION)
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [qti_default],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "strongbox",
                normalize_keymint_test_version,
            ),
            None
        );
    }

    #[test]
    fn explicit_usable_version_wins_over_omitted_default() {
        let omitted = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        let explicit = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        let unusable = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>99</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [explicit],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(4)
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [omitted, explicit],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(4)
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [explicit, omitted],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(4)
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [unusable],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            normalize_keymint_test_version(AIDL_OMITTED_VERSION)
        );
    }

    #[test]
    fn no_matching_instance_is_absent_not_omitted_default() {
        let unrelated = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.foo</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [unrelated],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            None
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                [],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            None
        );
        assert_eq!(
            resolve_aidl_hal_version_xmls(
                ["<manifest>", unrelated],
                KEYMINT_HAL_NAME,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                normalize_keymint_test_version,
            ),
            None
        );
    }
}
