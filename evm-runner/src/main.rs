use primitive_types::{H256};

fn main() {
  println!("Hello Test");
  // let h = H256 {
  //   ..Default::default()
  // };

  // let k = H256::repeat_byte(1);

  let num = 1;
  let k2 = H256::from_low_u64_be(num);

  println!("{:?}",k2);
}