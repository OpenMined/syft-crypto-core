use anyhow::Result;
use serde::Deserialize;
use serde_json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared application context derived from global CLI arguments.
#[derive(Debug, Clone)]
pub struct AppContext {
    pub vault_path: PathBuf,
    pub data_root: PathBuf,
    pub shadow_root: PathBuf,
}

pub fn resolve_vault(vault: Option<PathBuf>) -> PathBuf {
    let from_flag = vault;
    let from_env = env::var_os("SYC_VAULT").map(PathBuf::from);

    let candidate = from_flag.or(from_env).unwrap_or_else(default_vault_path);

    expand_home(candidate)
}

pub fn resolve_roots(
    data_override: Option<PathBuf>,
    shadow_override: Option<PathBuf>,
    vault: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let data_env = env::var_os("SYC_DATA_ROOT").map(PathBuf::from);
    let shadow_env = env::var_os("SYC_SHADOW_ROOT").map(PathBuf::from);

    let config = read_datasite_config(vault)?;

    let data_candidate = data_override
        .or(data_env)
        .or_else(|| config.as_ref().map(|cfg| cfg.encrypted_root.clone()));

    let shadow_candidate = shadow_override
        .or(shadow_env)
        .or_else(|| config.as_ref().map(|cfg| cfg.shadow_root.clone()));

    let data_root = data_candidate.ok_or_else(|| {
        anyhow::anyhow!("unable to determine data root – provide --data-root, set SYC_DATA_ROOT, or add encrypted_root to vault config")
    })?;

    let shadow_root = shadow_candidate.ok_or_else(|| {
        anyhow::anyhow!("unable to determine shadow root – provide --shadow-root, set SYC_SHADOW_ROOT, or add shadow_root to vault config")
    })?;

    Ok((expand_home(data_root), expand_home(shadow_root)))
}

pub fn ensure_vault_layout(vault: &Path) -> Result<()> {
    fs::create_dir_all(vault.join("keys"))?;
    fs::create_dir_all(vault.join("bundles"))?;
    fs::create_dir_all(vault.join("config")).ok();
    Ok(())
}

pub fn resolve_data_path(context: &AppContext, input: &Path) -> PathBuf {
    resolve_under_root(&context.data_root, input)
}

pub fn resolve_shadow_path(context: &AppContext, input: &Path) -> PathBuf {
    resolve_under_root(&context.shadow_root, input)
}

fn resolve_under_root(root: &Path, input: &Path) -> PathBuf {
    let expanded = expand_home(input);
    if expanded.is_absolute() {
        expanded
    } else {
        root.join(expanded)
    }
}

pub fn expand_home<P: AsRef<Path>>(input: P) -> PathBuf {
    let path = input.as_ref();
    let path_str = path.to_string_lossy();

    if path_str == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from("~"));
    }

    if let Some(stripped) = path_str.strip_prefix("~/") {
        return home_dir()
            .map(|home| home.join(stripped))
            .unwrap_or_else(|| PathBuf::from(path));
    }

    path.to_path_buf()
}

pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub fn bundle_path_for_identity(vault: &Path, identity: &str) -> PathBuf {
    let slug = sanitize_identity(identity);
    vault.join("bundles").join(format!("{slug}.json"))
}

pub fn key_path_for_identity(vault: &Path, identity: &str) -> PathBuf {
    let slug = sanitize_identity(identity);
    vault.join("keys").join(format!("{slug}.key"))
}

pub fn load_identity_label(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&contents)?;
    if let Some(identity) = value.get("identity").and_then(|v| v.as_str()) {
        return Ok(identity.to_string());
    }
    Err(anyhow::anyhow!(
        "unable to parse identity from {}",
        path.display()
    ))
}

pub fn read_identity_from_key(path: PathBuf) -> Result<String> {
    load_identity_label(&path)
}

pub fn fallback_identity_from_path(path: PathBuf) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn detect_single_identity(vault: &Path) -> Result<String> {
    let keys_dir = vault.join("keys");
    let mut identities = Vec::new();

    if keys_dir.exists() {
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let identity = read_identity_from_key(entry.path())
                    .unwrap_or_else(|_| fallback_identity_from_path(entry.path()));
                identities.push(identity);
            }
        }
    }

    match identities.len() {
        0 => Err(anyhow::anyhow!(
            "no identities found in vault (run `syc key generate` first)"
        )),
        1 => Ok(identities.remove(0)),
        _ => Err(anyhow::anyhow!(
            "multiple identities present – specify --sender/--identity"
        )),
    }
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = make_temp_path(path);
    fs::write(&tmp_path, data)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn read_datasite_config(vault: &Path) -> Result<Option<DatasiteConfig>> {
    let config_path = vault.join("config").join("datasite.json");
    if !config_path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&config_path)?;
    let raw: DatasiteConfigRaw = serde_json::from_str(&contents)?;
    let encrypted_root = resolve_config_path(vault, raw.encrypted_root)?;
    let shadow_root = resolve_config_path(vault, raw.shadow_root)?;

    Ok(Some(DatasiteConfig {
        encrypted_root,
        shadow_root,
    }))
}

fn resolve_config_path(vault: &Path, candidate: PathBuf) -> Result<PathBuf> {
    let expanded = expand_home(candidate);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        vault.join(expanded)
    };

    Ok(fs::canonicalize(&absolute).unwrap_or(absolute))
}

fn default_vault_path() -> PathBuf {
    home_dir()
        .map(|home| home.join(".syc"))
        .unwrap_or_else(|| PathBuf::from(".syc"))
}

/// Convert arbitrary identity strings into filesystem-safe slugs for bundle/key paths.
pub fn sanitize_identity(identity: &str) -> String {
    identity
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '@' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

pub fn resolve_identity(provided: Option<&str>, vault: &Path) -> Result<String> {
    match provided {
        Some(identity) => Ok(identity.to_owned()),
        None => detect_single_identity(vault),
    }
}

fn make_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("temp");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{stem}.{nanos}.tmp"))
}

#[derive(Deserialize, Debug, Clone)]
pub struct DatasiteConfigRaw {
    pub encrypted_root: PathBuf,
    pub shadow_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DatasiteConfig {
    pub encrypted_root: PathBuf,
    pub shadow_root: PathBuf,
}
