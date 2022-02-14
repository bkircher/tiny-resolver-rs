use eyre::{eyre, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::{env, process};
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;

fn resolve(name: &Name) -> Result<Ipv4Addr> {
    let mut nameserver = Ipv4Addr::new(198, 41, 0, 4);
    loop {
        let reply = dns_query(name, &nameserver)?;
        if let Some(ip) = get_answer(reply.answers()) {
            // Best case: we get an answer to our query and we're done
            return Ok(*ip);
        } else if let Some(ns_ip) = get_glue(reply.additionals()) {
            // Second best: we get a "glue record" with the *IP address* of
            // another nameserver to query
            nameserver = *ns_ip
        } else if let Some(domain) = get_ns(reply.name_servers()) {
            // Third best: we get the domain name of another nameserver to
            // query, which we can look up the IP for
            nameserver = resolve(domain)?;
        } else {
            // If there's no A record we just fail. This is also not a very good
            // resolver :)
            return Err(eyre!("Something went wrong"));
        }
    }
}

fn get_answer(answers: &[Record]) -> Option<&Ipv4Addr> {
    for rec in answers {
        if rec.record_type() == RecordType::A {
            println!(" {:?}", rec);
            if let &RData::A(ref ip) = rec.rdata() {
                return Some(ip);
            }
        }
    }
    None
}

fn get_glue(answers: &[Record]) -> Option<&Ipv4Addr> {
    for rec in answers {
        if rec.rr_type() == RecordType::A {
            println!(" {:?}", rec);
            if let &RData::A(ref ip) = rec.rdata() {
                return Some(ip);
            }
        }
    }
    None
}

fn get_ns(answers: &[Record]) -> Option<&Name> {
    for rec in answers {
        if rec.rr_type() == RecordType::NS {
            println!(" {:?}", rec);
            if let &RData::NS(ref name) = rec.rdata() {
                return Some(name);
            }
        }
    }
    None
}

fn dns_query(name: &Name, server: &Ipv4Addr) -> Result<DnsResponse> {
    println!("dig -r @{} {}", server, name);
    let addr = SocketAddr::new(IpAddr::V4(*server), 53);
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);
    client
        .query(name, DNSClass::IN, RecordType::A)
        .wrap_err_with(|| format!("Query failed"))
}

fn main() {
    let mut args = env::args();
    match args.nth(1) {
        None => {
            eprintln!("No name to resolve given");
            process::exit(1);
        }
        Some(mut name) => {
            if !name.ends_with('.') {
                name += ".";
            }
            let name = Name::from_str(&name).unwrap();
            let res = resolve(&name);
            println!("Result: {:?}", res);
        }
    }
}
