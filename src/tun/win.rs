//! Windows glue for the Wintun TUN (WIN-040..048): adapter addressing and
//! interface enumeration through IP Helper, and the per-network ICMP echo
//! firewall rules. Everything here runs on the adapter LUID, never through
//! `netsh` or PowerShell for the data plane.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, CreateUnicastIpAddressEntry,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetUnicastIpAddressTable,
    InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// IP Helper's `IpDadStatePreferred`: use the address at once, no duplicate
/// address detection on a point-to-point overlay.
const DAD_PREFERRED: i32 = 4;
/// `IpPrefixOriginManual` / `IpSuffixOriginManual`.
const ORIGIN_MANUAL: i32 = 1;

/// The adapter's LUID from its name (Wintun sets the interface alias to the
/// adapter name).
pub(super) fn luid_of(alias: &str) -> Result<u64> {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `wide` is NUL-terminated; `luid` is a writable out-parameter.
    let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    anyhow::ensure!(
        status == NO_ERROR,
        "adapter {alias} not found (Win32 error {status})"
    );
    // SAFETY: every NET_LUID_LH bit pattern is a valid u64.
    Ok(unsafe { luid.Value })
}

/// Every unicast address row of `family` (`AF_INET`, `AF_INET6` or
/// `AF_UNSPEC`), copied out of the IP Helper table.
fn unicast_rows(family: u16) -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: `table` receives a table this function frees with FreeMibTable.
    let status = unsafe { GetUnicastIpAddressTable(family, &mut table) };
    anyhow::ensure!(
        status == NO_ERROR && !table.is_null(),
        "listing unicast addresses failed (Win32 error {status})"
    );
    // SAFETY: on success `table` holds `NumEntries` initialized rows; they are
    // copied (plain data) before the table is freed.
    let rows = unsafe {
        let t = &*table;
        std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize).to_vec()
    };
    // SAFETY: allocated by GetUnicastIpAddressTable.
    unsafe { FreeMibTable(table.cast()) };
    Ok(rows)
}

fn row_v4(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<Ipv4Addr> {
    // SAFETY: the family tag says which union member is live.
    unsafe {
        (row.Address.si_family == AF_INET)
            .then(|| Ipv4Addr::from(u32::from_be(row.Address.Ipv4.sin_addr.S_un.S_addr)))
    }
}

fn row_v6(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<Ipv6Addr> {
    // SAFETY: the family tag says which union member is live.
    unsafe {
        (row.Address.si_family == AF_INET6)
            .then(|| Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte))
    }
}

/// Give the adapter exactly the node's overlay addresses (WIN-041, WIN-045):
/// delete every unicast address on it except `v4` (already assigned with the
/// network's netmask by the `tun` crate), then assign `v6` with on-link prefix
/// `v6_prefix`, from which Windows derives the network's /56 route.
pub(super) fn assign_addresses(luid: u64, v4: Ipv4Addr, v6: Ipv6Addr, v6_prefix: u8) -> Result<()> {
    let mut have_v6 = false;
    for row in unicast_rows(AF_UNSPEC)? {
        // SAFETY: every NET_LUID_LH bit pattern is a valid u64.
        if unsafe { row.InterfaceLuid.Value } != luid {
            continue;
        }
        if row_v4(&row) == Some(v4) {
            continue;
        }
        if row_v6(&row) == Some(v6) && row.OnLinkPrefixLength == v6_prefix {
            have_v6 = true;
            continue;
        }
        // A stale address from an earlier run of a reused adapter, or our own
        // v6 with the wrong prefix.
        // SAFETY: a row just read from the table identifies the address.
        let status = unsafe { DeleteUnicastIpAddressEntry(&row) };
        if status != NO_ERROR {
            tracing::warn!(
                status,
                "deleting a stale address on the tetron adapter failed"
            );
        }
    }
    if have_v6 {
        return Ok(());
    }
    // SAFETY: a zeroed row is valid input for InitializeUnicastIpAddressEntry,
    // which fills in the defaults; the fields set after it are plain data.
    let status = unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceLuid = NET_LUID_LH { Value: luid };
        row.Address.si_family = AF_INET6;
        row.Address.Ipv6.sin6_family = AF_INET6;
        row.Address.Ipv6.sin6_addr.u.Byte = v6.octets();
        row.OnLinkPrefixLength = v6_prefix;
        row.DadState = DAD_PREFERRED;
        row.PrefixOrigin = ORIGIN_MANUAL;
        row.SuffixOrigin = ORIGIN_MANUAL;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        CreateUnicastIpAddressEntry(&row)
    };
    anyhow::ensure!(
        status == NO_ERROR,
        "assigning {v6}/{v6_prefix} to the tetron adapter failed (Win32 error {status})"
    );
    Ok(())
}

fn alias_of(luid: NET_LUID_LH) -> Option<String> {
    let mut buf = [0u16; 257];
    // SAFETY: `buf` is writable for its full length, which is passed.
    let status = unsafe { ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) };
    (status == NO_ERROR).then(|| {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    })
}

/// Every local IPv4 unicast address with its on-link prefix and interface
/// alias, loopback skipped (WIN-043). Empty on failure (fail-open, as on the
/// other platforms).
pub(super) fn local_ipv4_interfaces() -> Vec<(String, Ipv4Addr, u8)> {
    let Ok(rows) = unicast_rows(AF_INET) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let addr = row_v4(row)?;
            if addr.is_loopback() {
                return None;
            }
            let name = alias_of(row.InterfaceLuid).unwrap_or_else(|| "unknown".to_string());
            Some((name, addr, row.OnLinkPrefixLength))
        })
        .collect()
}

/// Absolute path of `netsh.exe`, never resolved through `PATH`.
fn netsh() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::Path::new(&root)
        .join("System32")
        .join("netsh.exe")
}

/// Run netsh with a bounded wait; the output is not needed, only success.
fn run_netsh(args: &[String]) -> Result<()> {
    run_bounded(&netsh(), args)
}

/// Run `program` (an absolute path) with a bounded wait, discarding output.
fn run_bounded(program: &std::path::Path, args: &[String]) -> Result<()> {
    const LIMIT: Duration = Duration::from_secs(15);
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        if let Some(status) = child.try_wait().context("waiting for a child process")? {
            anyhow::ensure!(
                status.success(),
                "{} exited with {status}",
                program.display()
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            bail!("{} did not finish within {LIMIT:?}", program.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Firewall rule names for `adapter` (WIN-047).
fn rule_names(adapter: &str) -> [String; 2] {
    [
        format!("tetron {adapter} ICMPv4 echo"),
        format!("tetron {adapter} ICMPv6 echo"),
    ]
}

/// Delete `adapter`'s echo rules. A missing rule is not an error.
pub(super) fn remove_echo_rules(adapter: &str) {
    for name in rule_names(adapter) {
        let _ = run_netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={name}"),
        ]);
    }
}

/// (Re)create the two inbound echo-request rules for `adapter`, each scoped to
/// the node's own overlay address on it (WIN-047).
pub(super) fn install_echo_rules(adapter: &str, v4: Ipv4Addr, v6: Ipv6Addr) -> Result<()> {
    remove_echo_rules(adapter);
    let [n4, n6] = rule_names(adapter);
    for (name, proto, local) in [
        (n4, "icmpv4:8,any", v4.to_string()),
        (n6, "icmpv6:128,any", v6.to_string()),
    ] {
        run_netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={name}"),
            "dir=in".into(),
            "action=allow".into(),
            format!("protocol={proto}"),
            format!("localip={local}"),
        ])
        .with_context(|| format!("adding firewall rule {name}"))?;
    }
    Ok(())
}

/// Delete every tetron echo rule, of any adapter (WIN-055, uninstall). Matched
/// by the display names [`rule_names`] creates; PowerShell's rule cmdlets are
/// used because `netsh`'s listing is localized text.
/// PowerShell text for [`remove_all_echo_rules`]. Progress output is off: run
/// without a console of its own, `Remove-NetFirewallRule` deletes the rules,
/// then fails drawing its progress bar and exits 1 (WIN-087).
const REMOVE_ALL_ECHO_RULES_PS: &str = "$ProgressPreference = 'SilentlyContinue'; \
    Get-NetFirewallRule -DisplayName 'tetron tetron-* echo' -ErrorAction SilentlyContinue \
    | Remove-NetFirewallRule";

pub(super) fn remove_all_echo_rules() -> Result<()> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let ps = std::path::Path::new(&root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    run_bounded(
        &ps,
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            REMOVE_ALL_ECHO_RULES_PS.into(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // WIN-087: progress output off before the cmdlets run.
    #[test]
    fn echo_rule_cleanup_turns_progress_off_first() {
        let cmd = REMOVE_ALL_ECHO_RULES_PS;
        let progress = cmd
            .find("$ProgressPreference = 'SilentlyContinue';")
            .unwrap();
        assert!(progress < cmd.find("Get-NetFirewallRule").unwrap());
        assert!(cmd.ends_with("| Remove-NetFirewallRule"));
    }
}
