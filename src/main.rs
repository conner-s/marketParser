use std::{fs, env, process};
use pcap_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut r_arg: bool = false;
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Argument Error: Too little or too many arguments");
        process::exit(1);
    }
    else if args.len() = 3 {
        if args[2].matches("-r") {
            r_arg = true;
        }
        else {
            eprintln!("Unknown Argument");
            process::exit(1);
        }
    }

    let packet_path: String = args[1].clone();
    parse_packetFile(packet_path, r_arg);
}

fn parse_packetFile(Path: String, accept_ordering: bool) -> () {
    let open_file = fs::File::open(Path).expect("Could not find/open file");
    let pcap_reader = pcap_file::PcapReader::new(open_file).unwrap();
}

