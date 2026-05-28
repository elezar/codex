use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use codex_protocol::error::CodexErr;
use codex_protocol::error::Result;
use serde::Deserialize;

use crate::bwrap::DeviceBind;

const DEFAULT_CDI_SPEC_DIRS_BY_PRECEDENCE: &[&str] = &["/var/run/cdi", "/etc/cdi"];

pub(crate) fn resolve_default_cdi_device_binds(cdi_devices: &[String]) -> Result<Vec<DeviceBind>> {
    let spec_dirs_by_precedence = DEFAULT_CDI_SPEC_DIRS_BY_PRECEDENCE
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    resolve_cdi_device_binds(cdi_devices, &spec_dirs_by_precedence)
}

pub(crate) fn resolve_cdi_device_binds(
    cdi_devices: &[String],
    spec_dirs_by_precedence: &[PathBuf],
) -> Result<Vec<DeviceBind>> {
    if cdi_devices.is_empty() {
        return Ok(Vec::new());
    }

    let mut requested_devices = Vec::new();
    for device in cdi_devices {
        validate_qualified_name(device).map_err(|err| CodexErr::Fatal(err))?;
        if !requested_devices.iter().any(|existing| existing == device) {
            requested_devices.push(device.clone());
        }
    }

    let mut effective_devices = BTreeMap::new();
    let mut scan_errors = Vec::new();
    for spec_dir in spec_dirs_by_precedence.iter().rev() {
        let scan = scan_cdi_spec_dir(spec_dir);
        scan_errors.extend(scan.scan_errors);
        for (name, entry) in scan.entries {
            effective_devices.insert(name, entry);
        }
    }

    let mut resolved_devices = Vec::new();
    for device in &requested_devices {
        match effective_devices.get(device) {
            Some(EffectiveCdiDevice::Resolved(resolved)) => {
                resolved_devices.push((device.as_str(), resolved))
            }
            Some(EffectiveCdiDevice::InvalidDuplicate { message }) => {
                return Err(CodexErr::Fatal(message.clone()));
            }
            None => {
                return Err(CodexErr::Fatal(missing_device_message(
                    device,
                    spec_dirs_by_precedence,
                    &scan_errors,
                )));
            }
        }
    }

    let mut binds = Vec::new();
    let mut seen_binds = HashSet::new();
    let mut seen_global_edits = BTreeSet::new();
    for (requested_device, resolved_device) in resolved_devices {
        if seen_global_edits.insert(resolved_device.spec_path.clone()) {
            append_device_node_binds(
                requested_device,
                &resolved_device.spec_path,
                &resolved_device.global_device_nodes,
                &mut binds,
                &mut seen_binds,
            )?;
        }
        append_device_node_binds(
            requested_device,
            &resolved_device.spec_path,
            &resolved_device.device_nodes,
            &mut binds,
            &mut seen_binds,
        )?;
    }

    Ok(binds)
}

fn append_device_node_binds(
    requested_device: &str,
    spec_path: &Path,
    device_nodes: &[CdiDeviceNode],
    binds: &mut Vec<DeviceBind>,
    seen_binds: &mut HashSet<(PathBuf, PathBuf)>,
) -> Result<()> {
    for device_node in device_nodes {
        let destination = PathBuf::from(device_node.path.as_str());
        if !destination.is_absolute() {
            return Err(CodexErr::Fatal(format!(
                "CDI device `{requested_device}` in {} references non-absolute device node path `{}`",
                spec_path.display(),
                device_node.path
            )));
        }
        let source = device_node
            .host_path
            .as_ref()
            .map(|host_path| PathBuf::from(host_path.as_str()))
            .unwrap_or_else(|| destination.clone());
        if !source.is_absolute() {
            let host_path = device_node
                .host_path
                .as_deref()
                .unwrap_or(&device_node.path);
            return Err(CodexErr::Fatal(format!(
                "CDI device `{requested_device}` in {} references non-absolute host device node path `{host_path}`",
                spec_path.display(),
            )));
        }
        if !source.exists() {
            return Err(CodexErr::Fatal(format!(
                "CDI device `{requested_device}` requires missing host device node {}",
                source.display()
            )));
        }
        if seen_binds.insert((source.clone(), destination.clone())) {
            binds.push(DeviceBind {
                source,
                destination,
            });
        }
    }
    Ok(())
}

fn missing_device_message(
    device: &str,
    spec_dirs_by_precedence: &[PathBuf],
    scan_errors: &[String],
) -> String {
    let spec_dirs = spec_dirs_by_precedence
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut message = format!("CDI device `{device}` was not found in {spec_dirs}");
    if !scan_errors.is_empty() {
        message.push_str("; ignored malformed CDI specs: ");
        message.push_str(&scan_errors.join("; "));
    }
    message
}

#[derive(Debug, Default)]
struct DirectoryScan {
    entries: BTreeMap<String, EffectiveCdiDevice>,
    scan_errors: Vec<String>,
}

#[derive(Debug, Clone)]
enum EffectiveCdiDevice {
    Resolved(ResolvedCdiDevice),
    InvalidDuplicate { message: String },
}

#[derive(Debug, Clone)]
struct ResolvedCdiDevice {
    spec_path: PathBuf,
    global_device_nodes: Vec<CdiDeviceNode>,
    device_nodes: Vec<CdiDeviceNode>,
}

fn scan_cdi_spec_dir(spec_dir: &Path) -> DirectoryScan {
    let mut scan = DirectoryScan::default();
    let spec_files = match cdi_spec_files(spec_dir) {
        Ok(spec_files) => spec_files,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return scan,
        Err(err) => {
            scan.scan_errors.push(format!(
                "failed to read CDI spec directory {}: {err}",
                spec_dir.display()
            ));
            return scan;
        }
    };

    for spec_file in spec_files {
        match parse_cdi_spec_file(&spec_file) {
            Ok(spec) => {
                for device in spec.devices {
                    let duplicate_message = format!(
                        "CDI device `{}` is defined more than once in {}",
                        device.qualified_name,
                        spec_dir.display()
                    );
                    match scan.entries.get(&device.qualified_name) {
                        Some(EffectiveCdiDevice::Resolved(_)) => {
                            scan.entries.insert(
                                device.qualified_name,
                                EffectiveCdiDevice::InvalidDuplicate {
                                    message: duplicate_message,
                                },
                            );
                        }
                        Some(EffectiveCdiDevice::InvalidDuplicate { .. }) => {}
                        None => {
                            scan.entries.insert(
                                device.qualified_name,
                                EffectiveCdiDevice::Resolved(ResolvedCdiDevice {
                                    spec_path: spec.path.clone(),
                                    global_device_nodes: spec.global_device_nodes.clone(),
                                    device_nodes: device.device_nodes,
                                }),
                            );
                        }
                    }
                }
            }
            Err(err) => scan
                .scan_errors
                .push(format!("{}: {err}", spec_file.display())),
        }
    }

    scan
}

fn cdi_spec_files(spec_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut spec_files = Vec::new();
    collect_cdi_spec_files(spec_dir, &mut spec_files)?;
    spec_files.sort();
    Ok(spec_files)
}

fn collect_cdi_spec_files(dir: &Path, spec_files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_cdi_spec_files(&path, spec_files)?;
        } else if file_type.is_file() && is_cdi_spec_file(&path) {
            spec_files.push(path);
        }
    }
    Ok(())
}

fn is_cdi_spec_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "json" | "yaml" | "yml"))
}

#[derive(Debug)]
struct ParsedCdiSpec {
    path: PathBuf,
    global_device_nodes: Vec<CdiDeviceNode>,
    devices: Vec<ParsedCdiDevice>,
}

#[derive(Debug)]
struct ParsedCdiDevice {
    qualified_name: String,
    device_nodes: Vec<CdiDeviceNode>,
}

fn parse_cdi_spec_file(path: &Path) -> std::result::Result<ParsedCdiSpec, String> {
    let file =
        fs::File::open(path).map_err(|err| format!("failed to open CDI spec file: {err}"))?;
    let spec: CdiSpec =
        serde_yaml::from_reader(file).map_err(|err| format!("failed to parse CDI spec: {err}"))?;
    let CdiSpec {
        kind,
        devices,
        container_edits,
    } = spec;
    validate_kind(&kind)?;
    let devices = devices
        .into_iter()
        .map(|device| {
            validate_device_name(&device.name)?;
            Ok(ParsedCdiDevice {
                qualified_name: format!("{kind}={}", device.name),
                device_nodes: device.container_edits.device_nodes,
            })
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    Ok(ParsedCdiSpec {
        path: path.to_path_buf(),
        global_device_nodes: container_edits.device_nodes,
        devices,
    })
}

#[derive(Debug, Deserialize)]
struct CdiSpec {
    kind: String,
    #[serde(default)]
    devices: Vec<CdiDevice>,
    #[serde(rename = "containerEdits", default)]
    container_edits: CdiContainerEdits,
}

#[derive(Debug, Deserialize)]
struct CdiDevice {
    name: String,
    #[serde(rename = "containerEdits", default)]
    container_edits: CdiContainerEdits,
}

#[derive(Debug, Default, Deserialize)]
struct CdiContainerEdits {
    #[serde(rename = "deviceNodes", default)]
    device_nodes: Vec<CdiDeviceNode>,
}

#[derive(Debug, Clone, Deserialize)]
struct CdiDeviceNode {
    path: String,
    #[serde(rename = "hostPath")]
    host_path: Option<String>,
}

fn validate_qualified_name(device: &str) -> std::result::Result<(), String> {
    let Some((kind, name)) = device.split_once('=') else {
        return Err(format!(
            "CDI device `{device}` must be a fully qualified name of the form `vendor.com/class=device`"
        ));
    };
    if name.contains('=') {
        return Err(format!(
            "CDI device `{device}` must contain exactly one `=` separator"
        ));
    }
    validate_kind(kind)?;
    validate_device_name(name).map_err(|err| format!("invalid CDI device `{device}`: {err}"))
}

fn validate_kind(kind: &str) -> std::result::Result<(), String> {
    let Some((vendor, class)) = kind.split_once('/') else {
        return Err(format!(
            "CDI kind `{kind}` must be of the form `vendor.com/class`"
        ));
    };
    if class.contains('/') {
        return Err(format!(
            "CDI kind `{kind}` must contain exactly one `/` separator"
        ));
    }
    validate_vendor_or_class_name(vendor)
        .map_err(|err| format!("invalid CDI vendor in `{kind}`: {err}"))?;
    validate_vendor_or_class_name(class)
        .map_err(|err| format!("invalid CDI class in `{kind}`: {err}"))
}

fn validate_vendor_or_class_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("empty name".to_string());
    }
    if !name
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
    {
        return Err("name should start with a letter".to_string());
    }
    if let Some(character) = name.chars().find(|character| {
        !character.is_ascii_alphanumeric()
            && *character != '-'
            && *character != '_'
            && *character != '.'
    }) {
        return Err(format!("invalid character `{character}` in name `{name}`"));
    }
    Ok(())
}

fn validate_device_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("empty device name".to_string());
    }
    if let Some(character) = name.chars().find(|character| {
        !character.is_ascii_alphanumeric()
            && *character != '-'
            && *character != '_'
            && *character != '.'
            && *character != ':'
    }) {
        return Err(format!(
            "invalid character `{character}` in device name `{name}`"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[test]
    fn resolves_exact_device_nodes() {
        let temp_dir = TempDir::new().expect("temp dir");
        let spec_dir = temp_dir.path().join("cdi");
        let host_node = create_host_node(temp_dir.path(), "nvidia0");
        let shared_node = create_host_node(temp_dir.path(), "nvidiactl");
        write_spec(
            &spec_dir,
            "nvidia.yaml",
            &format!(
                r#"
cdiVersion: 0.7.0
kind: nvidia.com/gpu
containerEdits:
  deviceNodes:
    - path: {shared_node}
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
          hostPath: {host_node}
"#,
                shared_node = shared_node.display(),
                host_node = host_node.display()
            ),
        );

        let binds = resolve_cdi_device_binds(
            &["nvidia.com/gpu=0".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect("resolve CDI device");

        assert_eq!(
            binds,
            vec![
                DeviceBind {
                    source: shared_node.clone(),
                    destination: shared_node,
                },
                DeviceBind {
                    source: host_node,
                    destination: PathBuf::from("/dev/nvidia0"),
                },
            ]
        );
    }

    #[test]
    fn all_is_a_normal_device_name() {
        let temp_dir = TempDir::new().expect("temp dir");
        let spec_dir = temp_dir.path().join("cdi");
        let host_node = create_host_node(temp_dir.path(), "all");
        write_spec(
            &spec_dir,
            "gpu.yaml",
            &format!(
                r#"
cdiVersion: 0.7.0
kind: vendor.com/gpu
devices:
  - name: all
    containerEdits:
      deviceNodes:
        - path: /dev/vendor-all
          hostPath: {host_node}
"#,
                host_node = host_node.display()
            ),
        );

        let binds = resolve_cdi_device_binds(
            &["vendor.com/gpu=all".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect("resolve CDI device");

        assert_eq!(
            binds,
            vec![DeviceBind {
                source: host_node,
                destination: PathBuf::from("/dev/vendor-all"),
            }]
        );
    }

    #[test]
    fn all_is_not_expanded_when_not_defined() {
        let temp_dir = TempDir::new().expect("temp dir");
        let spec_dir = temp_dir.path().join("cdi");
        let host_node = create_host_node(temp_dir.path(), "zero");
        write_spec(
            &spec_dir,
            "gpu.yaml",
            &format!(
                r#"
cdiVersion: 0.7.0
kind: vendor.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/vendor0
          hostPath: {host_node}
"#,
                host_node = host_node.display()
            ),
        );

        let err = resolve_cdi_device_binds(
            &["vendor.com/gpu=all".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect_err("all must not expand");

        assert!(
            err.to_string()
                .contains("CDI device `vendor.com/gpu=all` was not found")
        );
    }

    #[test]
    fn malformed_specs_are_ignored_until_the_requested_device_is_missing() {
        let temp_dir = TempDir::new().expect("temp dir");
        let spec_dir = temp_dir.path().join("cdi");
        let host_node = create_host_node(temp_dir.path(), "good");
        write_spec(&spec_dir, "bad.yaml", "kind: [");
        write_spec(
            &spec_dir,
            "good.yaml",
            &format!(
                r#"
cdiVersion: 0.7.0
kind: vendor.com/gpu
devices:
  - name: good
    containerEdits:
      deviceNodes:
        - path: /dev/good
          hostPath: {host_node}
"#,
                host_node = host_node.display()
            ),
        );

        resolve_cdi_device_binds(
            &["vendor.com/gpu=good".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect("malformed unrelated spec should not fail requested device");

        let err = resolve_cdi_device_binds(
            &["vendor.com/gpu=missing".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect_err("missing requested device should report malformed specs");
        let message = err.to_string();
        assert!(message.contains("CDI device `vendor.com/gpu=missing` was not found"));
        assert!(message.contains("ignored malformed CDI specs"));
    }

    #[test]
    fn higher_precedence_directory_overrides_lower_precedence_directory() {
        let temp_dir = TempDir::new().expect("temp dir");
        let run_dir = temp_dir.path().join("run");
        let etc_dir = temp_dir.path().join("etc");
        let run_node = create_host_node(temp_dir.path(), "run");
        let etc_node = create_host_node(temp_dir.path(), "etc");
        write_device_spec(&etc_dir, "device.yaml", "vendor.com/gpu", "0", &etc_node);
        write_device_spec(&run_dir, "device.yaml", "vendor.com/gpu", "0", &run_node);

        let binds =
            resolve_cdi_device_binds(&["vendor.com/gpu=0".to_string()], &[run_dir, etc_dir])
                .expect("resolve CDI device");

        assert_eq!(
            binds,
            vec![DeviceBind {
                source: run_node,
                destination: PathBuf::from("/dev/test-device"),
            }]
        );
    }

    #[test]
    fn duplicate_devices_within_one_directory_are_invalid() {
        let temp_dir = TempDir::new().expect("temp dir");
        let spec_dir = temp_dir.path().join("cdi");
        let first_node = create_host_node(temp_dir.path(), "first");
        let second_node = create_host_node(temp_dir.path(), "second");
        write_device_spec(&spec_dir, "first.yaml", "vendor.com/gpu", "0", &first_node);
        write_device_spec(
            &spec_dir,
            "second.yaml",
            "vendor.com/gpu",
            "0",
            &second_node,
        );

        let err = resolve_cdi_device_binds(
            &["vendor.com/gpu=0".to_string()],
            std::slice::from_ref(&spec_dir),
        )
        .expect_err("duplicate requested device should fail");

        assert!(
            err.to_string()
                .contains("CDI device `vendor.com/gpu=0` is defined more than once")
        );
    }

    fn write_device_spec(
        spec_dir: &Path,
        relative_path: &str,
        kind: &str,
        name: &str,
        host_node: &Path,
    ) {
        write_spec(
            spec_dir,
            relative_path,
            &format!(
                r#"
cdiVersion: 0.7.0
kind: {kind}
devices:
  - name: "{name}"
    containerEdits:
      deviceNodes:
        - path: /dev/test-device
          hostPath: {host_node}
"#,
                host_node = host_node.display()
            ),
        );
    }

    fn write_spec(spec_dir: &Path, relative_path: &str, contents: &str) {
        let spec_file = spec_dir.join(relative_path);
        if let Some(parent) = spec_file.parent() {
            fs::create_dir_all(parent).expect("create spec directory");
        }
        fs::write(spec_file, contents).expect("write CDI spec");
    }

    fn create_host_node(temp_dir: &Path, name: &str) -> PathBuf {
        let node = temp_dir.join("dev").join(name);
        if let Some(parent) = node.parent() {
            fs::create_dir_all(parent).expect("create host device dir");
        }
        fs::write(&node, "").expect("create host node placeholder");
        node
    }
}
