use anyhow::{anyhow, Context, Ok};
use hex::{FromHex, ToHex};
use rand;
use serde_json::{self, Map};
use sha1::{Digest, Sha1};
use std::{
    env,
    io::{Read, Write},
};

fn decode_bencoded_value_u8(encoded_value: &[u8]) -> (Option<serde_json::Value>, &[u8]) {
    // If encoded_value starts with a digit, it's a number
    if encoded_value
        .iter()
        .next()
        .is_some_and(|&x| b'0' <= x && x <= b'9')
    {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value
            .iter()
            .enumerate()
            .filter(|(_, &x)| x == b':')
            .next()
            .unwrap()
            .0;
        let number_string = &encoded_value[..colon_index];
        let number = String::from_utf8_lossy(number_string)
            .parse::<i64>()
            .unwrap();

        if let Some(s) = encoded_value.get(colon_index + 1..colon_index + 1 + number as usize) {
            return (
                Some(serde_json::Value::String(
                    String::from_utf8_lossy(s).to_string(),
                )),
                &encoded_value[colon_index + 1 + number as usize..],
            );
        } else {
            return (
                Some(serde_json::Value::String(String::default())),
                &encoded_value[..],
            );
        }
    }
    let mut integeri64: Vec<u8> = Default::default();
    match &encoded_value.iter().enumerate().next().unwrap() {
        (idx, b'e') => {
            return (None, &encoded_value[idx + 1..]);
        }
        (idx, b'i') => {
            for &c in &encoded_value[idx + 1..] {
                if c == b'e' {
                    break;
                }
                if c == b'-' || (b'0' <= c && c <= b'9') {
                    integeri64.push(c);
                }
            }
            return (
                Some(serde_json::Value::Number(
                    String::from_utf8_lossy(&integeri64)
                        .parse::<i64>()
                        .unwrap()
                        .into(),
                )),
                &encoded_value[idx + integeri64.len() + 2..],
            );
        }
        (idx, b'l') => {
            let mut arr: Vec<serde_json::Value> = Default::default();
            let mut rest: &[u8] = &encoded_value[idx + 1..];

            loop {
                let (d, r) = decode_bencoded_value_u8(rest);
                if d.is_none() {
                    rest = r;
                    break;
                }
                arr.push(d.unwrap());
                rest = r;
            }
            return (Some(arr.into()), rest);
        }
        (idx, b'd') => {
            let mut map: Map<String, serde_json::Value> = Default::default();
            let mut rest: &[u8] = &encoded_value[idx + 1..];
            loop {
                let (k, r) = decode_bencoded_value_u8(rest);
                if k.is_none() {
                    rest = r;
                    break;
                }
                if k.as_ref().unwrap().is_string() {
                    if k.as_ref().unwrap() == "pieces" || k.as_ref().unwrap() == "peers" {
                        let (v, r) = decode_binary(r);
                        map.insert(k.unwrap().as_str().unwrap().to_string(), v);
                        rest = r;
                    } else {
                        if let (Some(v), r) = decode_bencoded_value_u8(r) {
                            map.insert(k.unwrap().as_str().unwrap().to_string(), v);
                            rest = r;
                        }
                    }
                } else {
                    panic!("key should be string!");
                }
            }
            return (Some(map.into()), rest);
        }
        _ => panic!("unexpected encoded value!"),
    }
}

fn decode_binary(encoded_value: &[u8]) -> (serde_json::Value, &[u8]) {
    let colon_index = encoded_value
        .iter()
        .enumerate()
        .filter(|(_, &x)| x == b':')
        .next()
        .unwrap()
        .0;
    let number_string = &encoded_value[..colon_index];
    let number = String::from_utf8_lossy(number_string)
        .parse::<i64>()
        .unwrap();

    let bin = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
    (
        serde_json::Value::String(bin.encode_hex()),
        &encoded_value[colon_index + 1 + number as usize..],
    )
}

fn peer_initial_tcp_conn(
    peer_addr: &str,
    infohash_20_bytes: &[u8],
    peeridstr: &str,
) -> anyhow::Result<std::net::TcpStream> {
    let handsake_payload = [19]
        .iter()
        .chain(b"BitTorrent protocol")
        .chain([0u8; 8].iter())
        .chain(infohash_20_bytes.iter())
        .chain(peeridstr.as_bytes())
        .cloned()
        .collect::<Vec<u8>>();
    println!(">>> {}", peer_addr);
    let mut tcpstream = std::net::TcpStream::connect(peer_addr).context("tcp connection")?;
    tcpstream
        .write_all(&handsake_payload)
        .context("tcpstream write handshake")?;
    let mut recv_handshake = [0u8; 68];
    tcpstream
        .read(&mut recv_handshake)
        .context("tcpstream read handshake")?;
    let peer_id = recv_handshake
        .iter()
        .rev()
        .take(20)
        .cloned()
        .collect::<Vec<u8>>();
    println!("Peer ID: {}", hex::encode(&peer_id));
    let mut payload_header = [0u8; 5];

    // recv bitfield(5)
    tcpstream
        .read_exact(&mut payload_header)
        .context("tcpstream read payload_header")?;

    let peer_payload_length = u32::from_be_bytes([
        payload_header[0],
        payload_header[1],
        payload_header[2],
        payload_header[3],
    ]);
    let mut payload = vec![0u8; peer_payload_length as usize - 1];
    tcpstream
        .read_exact(&mut payload)
        .context("tcpstream read payload")?;
    let msg_id = payload_header[4];

    println!("Peer Payload Length: {}", peer_payload_length);
    println!("Peer Payload Type: {}", msg_id);
    println!("Peer Payload: {:x?}", &payload);

    // send intrested(2)
    tcpstream.write(&[0, 0, 0, 1, 2])?;

    // recv unchoke(1)
    tcpstream.read_exact(&mut payload_header)?;
    println!("payload_header: {:x?}", payload_header);
    if payload_header[4] == 1 {
        Ok(tcpstream)
    } else {
        Err(anyhow!("Peer did not send unchoke message!"))
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let torrent_file = &args[1]; // Torrent file
    let mut file = std::fs::File::open(&torrent_file)?;
    let mut file_content: Vec<u8> = Default::default();
    file.read_to_end(&mut file_content)?;
    let decoded_value = decode_bencoded_value_u8(&file_content);
    let decoded_val = decoded_value.0.as_ref().unwrap();

    let destination = decoded_val["info"]["name"].as_str().unwrap();

    let info = &decoded_val["info"];
    let raw_pieces_hash = <Vec<u8>>::from_hex(info["pieces"].as_str().unwrap().as_bytes()).unwrap();
    if raw_pieces_hash.len() % 20 != 0 {
        panic!("piece hashes not multiple of 20!");
    }

    let mut pieces_hash: Vec<String> = Default::default();
    for i in (0..raw_pieces_hash.len()).step_by(20) {
        let p = &raw_pieces_hash[i..i + 20];
        pieces_hash.push(hex::encode(p));
    }
    let mut info_bencoded: Vec<u8> = format!(
        "d6:lengthi{}e4:name{}:{}12:piece lengthi{}e6:pieces{}:",
        &info["length"],
        info["name"].as_str().unwrap().len(),
        &info["name"].as_str().unwrap(),
        &info["piece length"],
        info["pieces"].as_str().unwrap().as_bytes().len() / 2,
    )
    .as_bytes()
    .iter()
    .chain(raw_pieces_hash.iter())
    .cloned()
    .collect();
    info_bencoded.push(b'e');

    let mut hasher = Sha1::new();
    hasher.update(&info_bencoded);

    let announce = &decoded_val["announce"];
    println!("TRACKER_URL: {announce}");
    let length = &decoded_val["info"]["length"];
    println!("LENGTH: {length}");
    let infohash_20_bytes: &[u8] = &hasher.finalize();
    let infohash = hex::encode(infohash_20_bytes);
    println!("INFO_HASH: {infohash}");
    let piece_length = &decoded_val["info"]["piece length"];
    println!("PIECE_LENGTH: {piece_length}");
    // println!("PIECE_HASHES:");
    // for x in &pieces_hash {
    //     println!("{x}");
    // }

    let len_str = length.to_string();
    let a = hex::decode(&infohash).unwrap();
    let mut urlencoded = String::with_capacity(3 * a.len());
    for b in &a {
        urlencoded.push('%');
        urlencoded.push_str(&hex::encode(&[*b]));
    }

    let mut peeridstr = String::new();
    for _ in 0..20 {
        peeridstr.push_str((rand::random::<u8>() % 10).to_string().as_str());
    }
    let port = announce
        .as_str()
        .unwrap()
        .split_once(':')
        .and_then(|(_, s2)| {
            s2.split_once(':')
                .and_then(|(_, x2)| x2.split_once('/').and_then(|(y1, _)| Some(y1)))
        })
        .unwrap_or("6881");

    let url = format!(
        "{}?peer_id={}&port={}&uploaded=0&downloaded=0&left={}&compact=1&info_hash={}",
        announce.as_str().unwrap(),
        &peeridstr,
        port,
        len_str,
        urlencoded.as_str()
    );
    println!("REQUEST_URL: {}", &url);

    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send()?;
    let tracker_resp_bencoded = response.bytes().expect("HTTP request failed!");
    println!(
        "RESPONSE: {}",
        String::from_utf8_lossy(&tracker_resp_bencoded)
    );
    let tracker_resp_decoded = decode_bencoded_value_u8(&tracker_resp_bencoded);
    println!("{}", tracker_resp_decoded.0.as_ref().unwrap());
    let tracker_resp_decoded_val = tracker_resp_decoded.0.unwrap();
    let (peers, _interval) = (
        tracker_resp_decoded_val["peers"].as_str().unwrap(),
        tracker_resp_decoded_val["interval"]
            .as_u64()
            .as_ref()
            .unwrap(),
    );
    let peers_bin = hex::decode(&peers)?;
    let mut peers_vec = Vec::<String>::new();
    println!("Peers IP:PORT:");
    let client_ip = reqwest::blocking::get("http://ifconfig.me")?.text()?;
    for peer in peers_bin.chunks(6) {
        let ip = &peer[0..4];
        let ipv4ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
        let ipv4port = u16::from_be_bytes([peer[4], peer[5]]);
        let p = format!("{}:{}", ipv4ip, ipv4port);
        if p.split_once(':').unwrap().0 == client_ip {
            continue;
        }
        peers_vec.push(p);
        println!("{}:{}", ipv4ip, ipv4port);
    }

    let mut tcpstream: Option<std::net::TcpStream> = None;
    for p in peers_vec.iter() {
        if let Some(t) = peer_initial_tcp_conn(p, &infohash_20_bytes, &peeridstr).ok() {
            tcpstream = Some(t);
            break;
        }
    }
    if tcpstream.is_none() {
        panic!("No peers send unchoke message!");
    }
    let mut tcpstream = tcpstream.unwrap();

    // send request(6) to each block
    let mut dest_file = std::fs::File::options()
        .append(true)
        .create(true)
        .open(&destination)?;

    let mut single_piece = Vec::<u8>::new();
    let mut peer_payload = [0u8; 13];
    let pieces_hash_len = pieces_hash.len();
    for p_idx in 0..pieces_hash_len {
        let p_len = if p_idx == pieces_hash.len() - 1 {
            let x = piece_length.as_u64().unwrap() as usize * (pieces_hash.len() - 1);
            length.to_string().parse::<usize>().unwrap() - x
        } else {
            piece_length.as_u64().unwrap() as usize
        };
        single_piece.reserve_exact(p_len as usize);
        let mut remainder_of_block: Option<u32> = None;
        let block_count = if p_len % (16 * 1024) == 0 {
            p_len as u32 / (16 * 1024) as u32
        } else {
            remainder_of_block = Some(p_len as u32 % (16 * 1024) as u32);
            (p_len as u32 / (16 * 1024) + 1) as u32
        };
        let mut begin = 0u32;
        let mut block_idx = 0u32;

        while begin < p_len as u32 {
            let rem = if block_idx == (block_count - 1) && remainder_of_block.is_some() {
                remainder_of_block.clone().unwrap()
            } else {
                16 * 1024 as u32
            };
            let p = 13u32
                .to_be_bytes()
                .iter()
                .chain([6].iter())
                .chain(&(p_idx as u32).to_be_bytes())
                .chain(&begin.to_be_bytes())
                .chain(&rem.to_be_bytes())
                .cloned()
                .collect::<Vec<_>>();
            tcpstream.write_all(&p)?;
            tcpstream.read_exact(&mut peer_payload)?;
            if peer_payload[4] != 7 {
                println!("peer_payload[4] is {}, retrying...", peer_payload[4]);
                continue;
            }
            let mut block = vec![0u8; rem as usize];
            tcpstream.read_exact(&mut block)?;
            single_piece.extend_from_slice(&block);
            begin += block.len() as u32;
            block_idx += 1;
        }
        println!(
            "Downloaded piece_{}/{} size: {}",
            p_idx,
            pieces_hash_len,
            single_piece.len()
        );
        let mut hasher_single_piece = Sha1::new();
        hasher_single_piece.update(&single_piece);
        let single_piece_hash_bytes: &[u8] = &hasher_single_piece.finalize();
        let single_piece_hash_str = hex::encode(&single_piece_hash_bytes);
        println!(
            "{} <=> {}",
            pieces_hash[p_idx as usize], &single_piece_hash_str
        );
        if pieces_hash[p_idx as usize] != single_piece_hash_str {
            panic!("Piece {p_idx}'s hash is not same!");
        }
        dest_file.write_all(&single_piece)?;
        single_piece.clear();
    }

    Ok(())
}
