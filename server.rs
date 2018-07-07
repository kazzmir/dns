use std::net::UdpSocket;
use std::str;

// extern crate bytes
// use bytes::{BytesMut, BufMut};

/* DNS Format:
 * Identity (2 bytes)
 * Query/Response (1 bit)
 * Opcode (4 bits)
 * Authoritative Answer (1 bit)
 * Truncation (1 bit)
 * Recursion desired (1 bit)
 * Recursion available (1 bit)
 * Zero (3 bits)
 * Response code (4 bits)
 * Question count (2 bytes)
 * Answer record (2 bytes)
 * Authority record count (2 bytes)
 * Additional record count (2 bytes)
 */

struct DNSHeader {
    identity: u16,
    /* QR - Z */
    question_response: bool, /* false for question, true for answer */
    opcode: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: u8,
    question_count: u16,
    answer_record: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

fn push_be_16(packet: &mut std::vec::Vec<u8>, value: u16){
    // let big = u16::to_be(value);
    let parts = [(value >> 8) as u8, (value & 0xff) as u8];
    packet.push(parts[0]);
    packet.push(parts[1]);
}

fn push_be_32(packet: &mut std::vec::Vec<u8>, value: u32){
    let parts = [(value >> 24) as u8,
                 ((value >> 16) & 0xff) as u8,
                 ((value >> 8) & 0xff) as u8,
                 ((value >> 0) & 0xff) as u8];
    packet.push(parts[0]);
    packet.push(parts[1]);
    packet.push(parts[2]);
    packet.push(parts[3]);
}

fn to_bit(x:bool) -> u8 {
    if x {
        return 1;
    } else {
        return 0;
    }
}

impl DNSHeader {
    fn is_question(&self) -> bool {
        return self.question_response == false;
    }

    fn is_answer(&self) -> bool {
        return ! self.is_question();
    }

    fn construct_data_bits(&self) -> u16 {
        return ((to_bit(self.question_response) as u16) << 15) |
               ((self.opcode as u16) << 11) |
               ((to_bit(self.authoritative_answer) as u16) << 10) |
               ((to_bit(self.truncation) as u16) << 9) |
               ((to_bit(self.recursion_desired) as u16) << 8) |
               ((to_bit(self.recursion_available) as u16) << 7) |
               ((self.response_code as u16) << 0);
    }

    fn serialize(&self, packet: &mut std::vec::Vec<u8>){
        push_be_16(packet, self.identity);
        push_be_16(packet, self.construct_data_bits());
        push_be_16(packet, self.question_count);
        push_be_16(packet, self.answer_record);
        push_be_16(packet, self.authority_record_count);
        push_be_16(packet, self.additional_record_count);
    }
}

#[derive(Debug)]
enum DNSType {
    A, /* IPV4 */
    AAAA, /* IPV6 */
    AFSDB,
    APL,
    CAA,
    CDNSKEY,
    CDS,
    CERT,
    CNAME,
    DHCID,
    DLV,
    DNAME,
    DNSKEY,
    DS,
    HIP,
    IPSECKEY,
    KEY,
    KX,
    LOC,
    MX,
    NAPTR,
    NS,
    NSEC,
    NSEC3,
    NSEC3PARAM,
    OPENPGPKEY,
    PTR,
    RRSIG,
    RP,
    SIG,
    SOA,
    SRV,
    SSHFP,
    TA,
    TKEY,
    TLSA,
    TSIG,
    TXT,
    URI
}

impl DNSType {
    fn value(&self) -> u16 {
        match self {
            &DNSType::A => {
                return 1;
            }
            _ => {
                return 0;
            }
        }
    }
}

impl std::fmt::Display for DNSType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(formatter, "{:?}", self);
    }
}

fn convert_question_type(value: u16) -> DNSType {
    match value {
        /* rust parser bug requires us to wrap return in {} */
        0x0 => {
            return DNSType::A;
        }
        28 => {
            return DNSType::AAAA;
        }
        18 => {
            return DNSType::AFSDB;
        }
        18 => {
            return DNSType::AFSDB;
        }
        42 => {
            return DNSType::APL;
        }
        257 => {
            return DNSType::CAA;
        }
        60 => {
            return DNSType::CDNSKEY;
        }
        59 => {
            return DNSType::CDS;
        }
        37 => {
            return DNSType::CERT;
        }
        5 => {
            return DNSType::CNAME;
        }
        49 => {
            return DNSType::DHCID;
        }
        32769 => {
            return DNSType::DLV;
        }
        39 => {
            return DNSType::DNAME;
        }
        48 => {
            return DNSType::DNSKEY;
        }
        43 => {
            return DNSType::DS;
        }
        55 => {
            return DNSType::HIP;
        }
        45 => {
            return DNSType::IPSECKEY;
        }
        25 => {
            return DNSType::KEY;
        }
        36 => {
            return DNSType::KX;
        }
        29 => {
            return DNSType::LOC;
        }
        15 => {
            return DNSType::MX;
        }
        35 => {
            return DNSType::NAPTR;
        }
        2 => {
            return DNSType::NS;
        }
        47 => {
            return DNSType::NSEC;
        }
        50 => {
            return DNSType::NSEC3;
        }
        51 => {
            return DNSType::NSEC3PARAM;
        }
        61 => {
            return DNSType::OPENPGPKEY;
        }
        12 => {
            return DNSType::PTR;
        }
        46 => {
            return DNSType::RRSIG;
        }
        17 => {
            return DNSType::RP;
        }
        24 => {
            return DNSType::SIG;
        }
        6 => {
            return DNSType::SOA;
        }
        33 => {
            return DNSType::SRV;
        }
        44 => {
            return DNSType::SSHFP;
        }
        32768 => {
            return DNSType::TA;
        }
        249 => {
            return DNSType::TKEY;
        }
        52 => {
            return DNSType::TLSA;
        }
        250  => {
            return DNSType::TSIG;
        }
        16 => {
            return DNSType::TXT;
        }
        256 => {
            return DNSType::URI;
        }

        /* FIXME: support more qtypes */
        _ => {
            return DNSType::A;
        }
    }
}

struct DNSQuestion {
    qname: String,
    qtype: DNSType,
    qclass: u16,
}

fn dns_zero(bits: u16) -> u8 {
    return (bits & 0b111) as u8;
}

struct ByteReader<'a>{
    buffer: &'a [u8],
    index: usize
}

impl<'a> ByteReader<'a>{
    fn read_be_16(&mut self) -> u16 {
        /*
        let value:u16 = u16::from_be(((self.buffer[self.index + 1] as u16) << 8) |
                                       self.buffer[self.index] as u16);
                                       */
        let value:u16 = ((self.buffer[self.index] as u16) << 8) |
                         self.buffer[self.index + 1] as u16;
        self.index += 2;
        return value;
    }
}

fn make_byte_reader(buffer: &[u8]) -> ByteReader {
    return ByteReader{
        buffer: buffer,
        index: 0
    }
}

fn dns_header_get_question_response(bits: u16) -> bool {
    return ((bits >> 15) & 0b1) == 0b1;
}

fn dns_header_get_opcode(bits: u16) -> u8 {
    return ((bits >> 11) & 0b1111) as u8;
}

fn dns_header_get_authoritative_answer(bits: u16) -> bool {
    return ((bits >> 10) & 0b1) == 0b1;
}

fn dns_header_get_truncation(bits: u16) -> bool {
    return ((bits >> 9) & 0b1) == 0b1;
}

fn dns_header_get_recursion_desired(bits: u16) -> bool {
    return ((bits >> 8) & 0b1) == 0b1;
}

fn dns_header_get_recursion_available(bits: u16) -> bool {
    return ((bits >> 7) & 0b1) == 0b1;
}

fn dns_header_get_response_code(bits: u16) -> u8 {
    return ((bits >> 0) & 0b1111) as u8;
}

/* FIXME: the type of buffer used to be [u8; 12] but it seems we have to convert
 * a slice into an array to achieve that.
 */
fn parse_dns_header(buffer: &[u8]) -> DNSHeader {
    let mut reader = make_byte_reader(buffer);

    let identity:u16 = reader.read_be_16();
    let data_bits:u16 = reader.read_be_16();
    let question_count:u16 = reader.read_be_16();
    let answer_record:u16 = reader.read_be_16();
    let authority_record_count:u16 = reader.read_be_16();
    let additional_record_count:u16 = reader.read_be_16();

    println!("Identity is {identity}", identity=identity);
    println!("Question count: {question}", question=question_count);
    println!("Zero field: {zero}", zero=dns_zero(data_bits));

    return DNSHeader{
        identity: identity,

        question_response: dns_header_get_question_response(data_bits),
        opcode: dns_header_get_opcode(data_bits),
        authoritative_answer: dns_header_get_authoritative_answer(data_bits),
        truncation: dns_header_get_truncation(data_bits),
        recursion_desired: dns_header_get_recursion_desired(data_bits),
        recursion_available: dns_header_get_recursion_available(data_bits),
        response_code: dns_header_get_response_code(data_bits),

        question_count: question_count,
        answer_record: answer_record,
        authority_record_count: authority_record_count,
        additional_record_count: additional_record_count,
    };
}

fn parse_dns_question(buffer: &[u8]) -> DNSQuestion {
    let mut index:usize = 0;
    let mut host_out:String = String::from("");
    let mut first:bool = true;
    loop {
        let length = buffer[index] as usize;
        if length == 0 {
            break
        }

        index += 1;

        println!("Length is {length}", length=length);
        /*
        for x in 0..length {
            let byte:u8 = buffer[(index + x) as usize];
            println!("Char {c} {d}", c=byte as char, d=byte);
        }
        */

        /* FIXME: bad to use unwrap here */
        let name = str::from_utf8(&buffer[index..(index+length)]).unwrap();
        println!("Name is {name}", name=name);

        if !first {
            host_out = host_out + ".";
        } else {
            first = false;
        }

        host_out = host_out + name;

        index += length;

        /*
        return DNSQuestion{
            qname: name.to_string(),
            qtype: 0,
            qclass: 0
        }
        */
    }

    index += 1;

    let mut reader = make_byte_reader(&buffer[index..(index+4)]);
    let qtype = reader.read_be_16();
    let qclass = reader.read_be_16();

    return DNSQuestion{
        qname: host_out,
        qtype: convert_question_type(qtype),
        qclass: qclass,
    };
}

type IPAddress = [u8; 4];

struct DNSAnswer {
    header: DNSHeader,
    name: String,
    qtype: DNSType,
    qclass: u16,
    time_to_live: u32, /* in seconds */
    response: IPAddress /* only works for A queries right now */
}

impl DNSAnswer {
    fn serialize(&self, packet: &mut std::vec::Vec<u8>){
        self.header.serialize(packet);
        /* question section */
        packet.push("google".chars().count() as u8);
        packet.extend_from_slice(&"google".as_bytes());
        packet.push("com".chars().count() as u8);
        packet.extend_from_slice(&"com".as_bytes());
        packet.push(0);
        push_be_16(packet, self.qtype.value());
        push_be_16(packet, self.qclass);


        /* answer section */
        push_be_16(packet, ((0b11 as u16) << 14) | 12);
        /*
        packet.push("google".chars().count() as u8);
        packet.extend_from_slice(&"google".as_bytes());
        packet.push("com".chars().count() as u8);
        packet.extend_from_slice(&"com".as_bytes());
        packet.push(0);
        */
        push_be_16(packet, self.qtype.value());
        push_be_16(packet, self.qclass);
        push_be_32(packet, self.time_to_live);
        // push_be_16(packet, self.time_to_live);
        push_be_16(packet, 4);
        packet.push(self.response[0]);
        packet.push(self.response[1]);
        packet.push(self.response[2]);
        packet.push(self.response[3]);
    }
}

/* FIXME: convert to enum */
const Success:u8 = 0;
const FormatError:u8 = 1;
const ServerFailure:u8 = 2;
const NameError:u8 = 3;
const NotImplemented:u8 = 4;
const Refused:u8 = 5;

fn make_ip(a: u8, b: u8, c: u8, d: u8) -> IPAddress {
    return [a, b, c, d];
}

fn ip_to_string(ip:IPAddress) -> String {
    return format!("{a}.{b}.{c}.{d}",
                   a = ip[0],
                   b = ip[1],
                   c = ip[2],
                   d = ip[3]);
}

fn construct_dns_answer(question_header: DNSHeader, question: DNSQuestion) -> DNSAnswer {
    let ip = make_ip(127, 0, 0, 1);
    return DNSAnswer{
        name: question.qname,
        qtype: question.qtype,
        qclass: question.qclass,
        time_to_live: 100,
        response: ip,
        header: DNSHeader{
            identity: question_header.identity,
            question_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: question_header.recursion_desired,
            recursion_available: true,
            response_code: Success,
            question_count: 1,
            answer_record: 1,
            authority_record_count: 0,
            additional_record_count: 0
        }
    };
}

fn dns_send_response(socket: &UdpSocket, source: &std::net::SocketAddr, answer: &DNSAnswer){
    let mut packet = std::vec::Vec::with_capacity(128);

    answer.serialize(&mut packet);

    let _ = socket.send_to(&packet, &source);
}

fn serve(socket: &UdpSocket){
  let mut buffer = [0; 4096];
  let (amount, source) = socket.recv_from(&mut buffer).unwrap();
  println!("Received {bytes} {source}", bytes=amount, source=source);
  /* Create a slice out of an array */
  let header = parse_dns_header(&buffer[0..12]);
  let question = parse_dns_question(&buffer[12..4096]);
  println!("Question header {question}", question=header.is_question());
  println!("Request for '{host}' type {qtype}", host=question.qname, qtype=question.qtype);
  let answer = construct_dns_answer(header, question);
  println!("Answer for '{host}' is {ip}", host=answer.name, ip=ip_to_string(answer.response));

  dns_send_response(&socket, &source, &answer)
}

fn main(){
  let port = 5553;
  let socket = UdpSocket::bind(format!("127.0.0.1:{port}", port=port)).unwrap();
  println!("Running DNS server on port {port}", port=port);
  while true {
    serve(&socket)
  }
}
