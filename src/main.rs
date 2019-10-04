use std::{fs, env, process, str};
use pcap_file;
use chrono;
use multimap::MultiMap;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut r_arg: bool = false;
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Argument Error: Too little or too many arguments");
        process::exit(1);
    } else if args.len() == 3 {
        if args[2].contains("-r") {
            r_arg = true;
        } else {
            eprintln!("Unknown Argument");
            process::exit(1);
        }
    }

    let packet_path: String = args[1].clone();

    if r_arg {
        print_ordered(packet_path);
    } else {
       print_unordered(packet_path);
    }
}

fn print_ordered(path: String) -> () {
    let open_file = fs::File::open(path).expect("Could not find/open file");
    let pcap_reader = pcap_file::PcapReader::new(open_file).unwrap();
    let mut packet_list: Vec<pcap_file::Packet> = Vec::new();

    //populate Vector with valid necessary packets
    for packet in pcap_reader {
        let packet = packet.unwrap();
        let should_add = valid_packet(&packet);
        if should_add { packet_list.push(packet);}
    }

    //Creating multimap to correlate times with packet indexes
    //Using multimap because some packets can have the same accept-time
    let mut time_map = MultiMap::new();
    //Creating vector that will be used to sort said times
    let mut time_vec: Vec<u32> = Vec::new();
    let mut workingpos: usize = 0;

    for packet in &packet_list {
        let time = packet.data[248..256].to_ascii_lowercase();
        let time_str = str::from_utf8(&time).unwrap();
        let time_num = time_str.parse::<u32>().unwrap();
        time_map.insert(time_num, workingpos);
        time_vec.push(time_num);
        workingpos += 1;

    }
    time_vec.sort();

    for time in time_vec {
        let time_indexes = time_map.get_vec(&time).unwrap();
        for item in time_indexes {
            let index_to_print = item.clone();
            print_packet(&packet_list.get(index_to_print).unwrap());

        }
    }

}

fn print_unordered(path: String) -> () {
    let open_file = fs::File::open(path).expect("Could not find/open file");
    let pcap_reader = pcap_file::PcapReader::new(open_file).unwrap();

    for packet in pcap_reader {
        let packet = packet.unwrap();
        let should_search = valid_packet(&packet);

        //Checks to see if packet is long enough to contain data then checks to see if it contain b6034

        if should_search {
            print_packet(&packet);
        }
    }
}

//Prints a given packet in proper syntax
fn print_packet(packet: &pcap_file::Packet) {

    //Packet timestamp
    let nano = packet.header.ts_usec * 1000;
    let packet_date_time = chrono::NaiveDateTime::from_timestamp(packet.header.ts_sec as i64, nano);
    print!("<{}> ", packet_date_time.time());

    //Accept-time Timestamp Extraction/Print
    let accept_time_hr = packet.data[248..250].to_ascii_lowercase();
    let accept_time_hr_str = str::from_utf8(&accept_time_hr).unwrap();

    let accept_time_min = packet.data[250..252].to_ascii_lowercase();
    let accept_time_min_str = str::from_utf8(&accept_time_min).unwrap();

    let accept_time_sec = packet.data[252..254].to_ascii_lowercase();
    let accept_time_sec_str = str::from_utf8(&accept_time_sec).unwrap();

    let accept_time_micro = packet.data[254..256].to_ascii_lowercase();
    let accept_time_micro_str = str::from_utf8(&accept_time_micro).unwrap();
    print!("<{}:{}:{}.{}> ", accept_time_hr_str, accept_time_min_str, accept_time_sec_str, accept_time_micro_str);


    //Issue Code Extraction/Print
    let issue_code = packet.data[47..59].to_ascii_lowercase();
    let issue_code_str = str::from_utf8(&issue_code).unwrap();
    print!("<{}> ", issue_code_str);


    //Bid 5-1 Quantity and Price
    //Loops through the byte indexes of the 5 Bid quantities and prices
    //and prints them out in reverse order
    let mut working_pos = 124;
    for _i in 0..5 {
        let bid_q = packet.data[working_pos..working_pos +7].to_ascii_lowercase();
        let bid_qstr = str::from_utf8(&bid_q).unwrap();
        working_pos = working_pos - 5;

        let bid_p = packet.data[working_pos..working_pos +5].to_ascii_lowercase();
        let bid_pstr = str::from_utf8(&bid_p).unwrap();
        working_pos =  working_pos - 7;
        print!("<{}> @ <{}> ", bid_qstr, bid_pstr);
    }

    //Ask 1-5 Quantity and Price
    //Loops through the byte indexes of the 5 Ask quantities and prices and prints them out in order
    let mut working_pos = 143;
    for _p in 0..5 {
        let ask_q = packet.data[working_pos..working_pos +7].to_ascii_lowercase();
        let ask_qstr = str::from_utf8(&ask_q).unwrap();
        working_pos = working_pos - 5;

        let ask_p = packet.data[working_pos..working_pos +5].to_ascii_lowercase();
        let ask_pstr = str::from_utf8(&ask_p).unwrap();
        working_pos =  working_pos + 12;
        print!("<{}> @ <{}> ", ask_qstr, ask_pstr);
    }

    println!();
}


//Checks to see if packet is long enough to contain data then checks to see if it contain b6034
fn valid_packet(packet: &pcap_file::Packet) -> bool {
    let mut should_search = true;
    //Check to see if packet is even long enough to contain the string
    if packet.header.orig_len > 47 {
        //Stores correct string ascii codes
        let check_code: Vec<u8> = vec![98, 54, 48, 51, 52];
        //pulls ascii codes from packet
        let packet_code = packet.data[42..47].to_ascii_lowercase();
        let mut workingpos = 0;
        for byte in check_code {
            if byte != packet_code[workingpos] {
                should_search = false;
            }
            workingpos += 1;
        }
    } else {
        should_search = false;
    }
    should_search
}
