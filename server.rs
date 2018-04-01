use std::net::UdpSocket;

fn main(){
  let port = 5553;
  let socket = UdpSocket::bind(format!("127.0.0.1:{port}", port=port)).unwrap();
  println!("Running server on port {port}", port=port);
  let mut buffer = [0; 100];
  let (amount, source) = socket.recv_from(&mut buffer).unwrap();
  println!("Received {bytes} {source}", bytes=amount, source=source);
}
