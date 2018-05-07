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
    data_bits: u16,
    question_count: u16,
    answer_record: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

fn dns_zero(bits: u16) -> u8 {
    return (bits & 0b111) as u8;
}

struct ByteReader<'a>{
    buffer: &'a [u8],
    index: usize
}

trait Reader{
    fn read_le_16(&mut self) -> u16;
}

impl<'a> Reader for ByteReader<'a> {
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
        data_bits: data_bits,
        question_count: question_count,
        answer_record: answer_record,
        authority_record_count: authority_record_count,
        additional_record_count: additional_record_count,
    };
}

fn parse_dns_question(buffer: &[u8]) -> DNSQuestion {
    let mut index:u8 = 0;
    loop {
        let length = buffer[index as usize];
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
        let name = str::from_utf8(&buffer[index as usize..(index+length) as usize]).unwrap();
        println!("Name is {name}", name=name);

        index += length;
    }

    return DNSQuestion{
        qname: "".to_string(),
        qtype: 0,
        qclass: 0,
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
}
