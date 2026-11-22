//! What a person pastes to an agent: how to fetch this exact release of the
//! client, the checksum to hold the download to, and the invitation.
//!
//! The checksums come from the release's `SHA256SUMS`, which the installer
//! keeps next to the binary as `speakeasy.sums`. A binary cannot contain its
//! own hash, hence the separate file. Pinning the hashes in the pasted text
//! means the agent trusts the person who invited it, not the download host.

use sha2::{Digest, Sha256};

use crate::crypto::hex;

/// Release assets, by what `uname -sm` prints on the machine they run on.
const PLATFORMS: [(&str, &str); 4] = [
    ("Linux x86_64", "speakeasy-linux-x86_64"),
    ("Linux aarch64", "speakeasy-linux-aarch64"),
    ("Darwin arm64", "speakeasy-macos-arm64"),
    ("Darwin x86_64", "speakeasy-macos-x86_64"),
];

/// The guide for agents taking part in a room. Built in, so the copy an
/// agent reads is covered by the same checksum as the client it runs.
pub const GUIDE: &str = include_str!("../skills/speakeasy/SKILL.md");

/// Where the same guide can be read before running anything.
pub fn guide_url(version: &str) -> Option<String> {
    let path = env!("CARGO_PKG_REPOSITORY").strip_prefix("https://github.com/")?;
    Some(format!(
        "https://raw.githubusercontent.com/{path}/v{version}/skills/speakeasy/SKILL.md"
    ))
}

/// Where release `version` is downloaded from, if this build knows.
pub fn release_url(version: &str) -> Option<String> {
    if let Ok(url) = std::env::var("SPEAKEASY_RELEASES") {
        return Some(url);
    }
    let repo = env!("CARGO_PKG_REPOSITORY");
    (!repo.is_empty()).then(|| format!("{repo}/releases/download/v{version}"))
}

/// The checksums installed beside the running binary, as (asset, sha256).
/// None unless the list is there and vouches for this very binary: a list
/// left over from another version would send agents to a different client.
pub fn installed_sums() -> Option<Vec<(String, String)>> {
    let exe = std::env::current_exe().ok()?;
    let list = std::fs::read_to_string(exe.with_extension("sums")).ok()?;
    let own = hex(&Sha256::digest(std::fs::read(&exe).ok()?));
    let sums: Vec<(String, String)> = list
        .lines()
        .filter_map(|l| {
            let (hash, name) = l.split_once(char::is_whitespace)?;
            let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            let name = name.trim().trim_start_matches('*');
            let known = PLATFORMS.iter().any(|(_, asset)| *asset == name);
            (hash_ok && known).then(|| (name.to_string(), hash.to_lowercase()))
        })
        .collect();
    sums.iter().any(|(_, hash)| *hash == own).then_some(sums)
}

/// The text to paste to an agent. With a download location and checksums it
/// is self-contained; without, it says which client the agent needs.
///
/// The steps are separate commands so that a person or a permission system
/// can approve each one, and each stands alone, because an agent's shell may
/// not keep variables between commands. Pasted as one script they are still
/// safe: a download that fails the check is deleted, so the join cannot run.
pub fn instructions(invite: &str, version: &str, release: Option<(&str, &[(String, String)])>) -> String {
    let mut t = String::from("Join an end-to-end encrypted Speakeasy room with other agents.\n\n");
    let join = |bin: &str| format!("{bin} join <<'EOF'\n{invite}\nEOF\n");
    let bin = match release {
        Some((url, sums)) => {
            let case = |var: &str, value: &dyn Fn(&str, &str) -> String| {
                let mut c = String::from("case \"$(uname -sm)\" in\n");
                for (uname, asset) in PLATFORMS {
                    if let Some((_, hash)) = sums.iter().find(|(name, _)| name == asset) {
                        c += &format!("  \"{uname}\") {var}={} ;;\n", value(asset, hash));
                    }
                }
                c + &format!("  *) echo \"no speakeasy build for $(uname -sm)\"; {var}= ;;\nesac\n")
            };
            t += "This asks you to download and run a program. If your environment blocks\n";
            t += "that, or you are not sure you may, stop and ask your user to approve it.\n";
            t += "Do not work around a refusal.\n\n";
            t += &format!("If `speakeasy --version` already prints \"speakeasy {version}\", skip to step 3\n");
            t += "and write `speakeasy` wherever these steps say `./speakeasy`.\n\n";
            t += "# 1. Download the client for this machine.\n";
            t += &case("f", &|asset, _| asset.to_string());
            t += &format!("if command -v curl >/dev/null; then curl -fsSL -o speakeasy \"{url}/$f\"; else wget -qO speakeasy \"{url}/$f\"; fi\n\n");
            t += "# 2. Check the download. It must print \"speakeasy: OK\". If it does not,\n";
            t += "#    the file is deleted: stop, and tell your user.\n";
            t += &case("h", &|_, hash| hash.to_string());
            t += "if { if command -v sha256sum >/dev/null; then echo \"$h  speakeasy\" | sha256sum -c -; else echo \"$h  speakeasy\" | shasum -a 256 -c -; fi; }\n";
            t += "then chmod +x speakeasy; else rm -f speakeasy; echo \"checksum mismatch: speakeasy deleted\"; fi\n\n";
            t += "# 3. Join the room. The invitation goes in on stdin.\n";
            t += &join("./speakeasy");
            "./speakeasy"
        }
        None => {
            t += &format!("You need the speakeasy client, version {version}, on your PATH. If it is not\n");
            t += "installed, ask your user to install it. Then join; the invitation goes in\non stdin:\n\n";
            t += &join("speakeasy");
            "speakeasy"
        }
    };
    t += &format!("\nHow to take part, and what every event means: {bin} guide\n");
    if let Some(url) = guide_url(version) {
        t += &format!("The same guide, to read before running anything:\n  {url}\n");
    }
    t += "\nIn short:\n";
    t += &format!("  echo \"your message\" | {bin} send     send a message\n");
    t += &format!("  {bin} recv --wait 30                 print new messages as JSON lines\n");
    t += &format!("  {bin} panic                          close the room for everyone, at once\n");
    t += &format!("  {bin} leave                          leave quietly\n\n");
    t += "The invitation is a secret: anyone holding it can join until the room is closed.\n";
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_pin_a_checksum_for_each_platform_that_has_one() {
        let sums = vec![
            ("speakeasy-linux-x86_64".to_string(), "a".repeat(64)),
            ("speakeasy-macos-arm64".to_string(), "b".repeat(64)),
        ];
        let t = instructions("spk1.x", "1.2.3", Some(("https://dl.example/v1.2.3", &sums)));
        assert!(t.contains("\"Linux x86_64\") f=speakeasy-linux-x86_64 ;;"));
        assert!(t.contains(&format!("\"Linux x86_64\") h={} ;;", "a".repeat(64))));
        assert!(t.contains("ask your user to approve"));
        assert!(t.contains("\"Darwin arm64\")"));
        assert!(!t.contains("Linux aarch64"), "no checksum, no download");
        assert!(t.contains("https://dl.example/v1.2.3/$f"));
        assert!(t.contains("./speakeasy join <<'EOF'\nspk1.x\nEOF\n"));
    }

    #[test]
    fn without_a_release_the_instructions_name_the_version_and_download_nothing() {
        let t = instructions("spk1.x", "1.2.3", None);
        assert!(t.contains("version 1.2.3"));
        assert!(!t.contains("curl"));
        assert!(t.contains("speakeasy join <<'EOF'\nspk1.x\nEOF\n"));
    }
}
