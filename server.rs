use std::net::UdpSocket;
use std::str;

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

impl DNSHeader {
    fn is_question(&self) -> bool {
        return self.question_response == false;
    }

    fn is_answer(&self) -> bool {
        return ! self.is_question();
    }
}

#[derive(Debug)]
enum QuestionType {
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

impl std::fmt::Display for QuestionType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(formatter, "{:?}", self);
    }
}

fn convert_question_type(value: u16) -> QuestionType {
    match value {
        /* rust parser bug requires us to wrap return in {} */
        0x0 => {
            return QuestionType::A;
        }
        28 => {
            return QuestionType::AAAA;
        }
        18 => {
            return QuestionType::AFSDB;
        }
        18 => {
            return QuestionType::AFSDB;
        }
        42 => {
            return QuestionType::APL;
        }
        257 => {
            return QuestionType::CAA;
        }
        60 => {
            return QuestionType::CDNSKEY;
        }
        59 => {
            return QuestionType::CDS;
        }
        37 => {
            return QuestionType::CERT;
        }
        5 => {
            return QuestionType::CNAME;
        }
        49 => {
            return QuestionType::DHCID;
        }
        32769 => {
            return QuestionType::DLV;
        }
        39 => {
            return QuestionType::DNAME;
        }
        48 => {
            return QuestionType::DNSKEY;
        }
        43 => {
            return QuestionType::DS;
        }
        55 => {
            return QuestionType::HIP;
        }
        45 => {
            return QuestionType::IPSECKEY;
        }
        25 => {
            return QuestionType::KEY;
        }
        36 => {
            return QuestionType::KX;
        }
        29 => {
            return QuestionType::LOC;
        }
        15 => {
            return QuestionType::MX;
        }
        35 => {
            return QuestionType::NAPTR;
        }
        2 => {
            return QuestionType::NS;
        }
        47 => {
            return QuestionType::NSEC;
        }
        50 => {
            return QuestionType::NSEC3;
        }
        51 => {
            return QuestionType::NSEC3PARAM;
        }
        61 => {
            return QuestionType::OPENPGPKEY;
        }
        12 => {
            return QuestionType::PTR;
        }
        46 => {
            return QuestionType::RRSIG;
        }
        17 => {
            return QuestionType::RP;
        }
        24 => {
            return QuestionType::SIG;
        }
        6 => {
            return QuestionType::SOA;
        }
        33 => {
            return QuestionType::SRV;
        }
        44 => {
            return QuestionType::SSHFP;
        }
        32768 => {
            return QuestionType::TA;
        }
        249 => {
            return QuestionType::TKEY;
        }
        52 => {
            return QuestionType::TLSA;
        }
        250  => {
            return QuestionType::TSIG;
        }
        16 => {
            return QuestionType::TXT;
        }
        256 => {
            return QuestionType::URI;
        }

        /* FIXME: support more qtypes */
        _ => {
            return QuestionType::A;
        }
    }
}

struct DNSQuestion {
    qname: String,
    qtype: QuestionType,
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
    fn read_le_16(&mut self) -> u16 {
        let value:u16 = u16::from_le(((self.buffer[self.index] as u16) << 8) |
                                       self.buffer[self.index + 1] as u16);
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
    return (bits & 0b1) == 0b1;
}

fn dns_header_get_opcode(bits: u16) -> u8 {
    return ((bits >> 1) & 0b1111) as u8;
}

fn dns_header_get_authoritative_answer(bits: u16) -> bool {
    return ((bits >> 4) & 0b1) == 0b1;
}

fn dns_header_get_truncation(bits: u16) -> bool {
    return ((bits >> 5) & 0b1) == 0b1;
}

fn dns_header_get_recursion_desired(bits: u16) -> bool {
    return ((bits >> 6) & 0b1) == 0b1;
}

fn dns_header_get_recursion_available(bits: u16) -> bool {
    return ((bits >> 7) & 0b1) == 0b1;
}

fn dns_header_get_response_code(bits: u16) -> u8 {
    return ((bits >> 11) & 0b1111) as u8;
}

/* FIXME: the type of buffer used to be [u8; 12] but it seems we have to convert
 * a slice into an array to achieve that.
 */
fn parse_dns_header(buffer: &[u8]) -> DNSHeader {
    let mut reader = make_byte_reader(buffer);

    let identity:u16 = reader.read_le_16();
    let data_bits:u16 = reader.read_le_16();
    let question_count:u16 = reader.read_le_16();
    let answer_record:u16 = reader.read_le_16();
    let authority_record_count:u16 = reader.read_le_16();
    let additional_record_count:u16 = reader.read_le_16();

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
    let qtype = reader.read_le_16();
    let qclass = reader.read_le_16();

    return DNSQuestion{
        qname: host_out,
        qtype: convert_question_type(qtype),
        qclass: qclass,
    };
}

struct DNSAnswer {
    header: DNSHeader,
}

const Success:u8 = 0;
const FormatError:u8 = 1;
const ServerFailure:u8 = 2;
const NameError:u8 = 3;
const NotImplemented:u8 = 4;
const Refused:u8 = 5;

fn construct_dns_answer(question_header: DNSHeader, question: DNSQuestion) -> DNSAnswer {
    return DNSAnswer{
        header: DNSHeader{
            identity: question_header.identity,
            question_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: Success,
            question_count: 0,
            answer_record: 1,
            authority_record_count: 0,
            additional_record_count: 0
        }
    };
}

fn main(){
  let port = 5553;
  let socket = UdpSocket::bind(format!("127.0.0.1:{port}", port=port)).unwrap();
  println!("Running DNS server on port {port}", port=port);
  let mut buffer = [0; 4096];
  let (amount, source) = socket.recv_from(&mut buffer).unwrap();
  println!("Received {bytes} {source}", bytes=amount, source=source);
  /* Create a slice out of an array */
  let header = parse_dns_header(&buffer[0..12]);
  let question = parse_dns_question(&buffer[12..4096]);
  println!("Question header {question}", question=header.is_question());
  println!("Request for '{host}' type {qtype}", host=question.qname, qtype=question.qtype);
  let answer = construct_dns_answer(header, question);
}
