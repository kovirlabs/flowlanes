//! Parsing of Linux `/proc/net/udp` and `/proc/net/udp6`. Compiled on every
//! OS so its test runs everywhere; used only on Linux.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// Sum of the `drops` column over the sockets bound to `port`, or `None`
/// when the text has no `drops` column or no socket on that port.
///
/// The table's header is `sl local_address rem_address st tx_queue rx_queue
/// tr tm->when retrnsmt uid timeout inode ref pointer drops`; `drops` is the
/// last column and `local_address` is `HEXADDR:HEXPORT`.
pub fn drops_for_port(table: &str, port: u16) -> Option<u64> {
    let mut lines = table.lines();
    let header = lines.next()?;
    if header.split_whitespace().last() != Some("drops") {
        return None;
    }
    let mut total = None;
    for line in lines {
        let mut cols = line.split_whitespace();
        let (Some(_sl), Some(local)) = (cols.next(), cols.next()) else {
            continue;
        };
        let Some((_, p)) = local.rsplit_once(':') else {
            continue;
        };
        if u16::from_str_radix(p, 16) != Ok(port) {
            continue;
        }
        if let Some(Ok(d)) = cols.last().map(str::parse::<u64>) {
            total = Some(total.unwrap_or(0) + d);
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::drops_for_port;

    // Layout as printed by the kernel; the addresses are loopback and the
    // numbers are made up.
    const TABLE: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   16: 0100007F:0807 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9486 2 0000000000000000 41
   99: 0100007F:007B 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9487 2 0000000000000000 7
";

    #[test]
    fn finds_the_drops_of_the_socket_on_a_port() {
        assert_eq!(drops_for_port(TABLE, 2055), Some(41));
        assert_eq!(drops_for_port(TABLE, 123), Some(7));
        assert_eq!(drops_for_port(TABLE, 9), None);
        assert_eq!(drops_for_port("sl local_address\n", 2055), None);
        assert_eq!(drops_for_port("", 2055), None);
    }
}
