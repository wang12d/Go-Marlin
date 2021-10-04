use crate::{Field, field_encode_convert};

pub fn convert_bytes_to_field_elements<F: Field>(bytes: &Vec<u8>, field_size: usize) -> Vec<F> {
    let length = bytes.len();
    let mut index = 0;
    let mut field_elements = Vec::new();
    while index < length {
        let mut next = index + field_size;
        if next > length {
            next = length;
        }
        field_elements.push(F::read(&field_encode_convert(&bytes[index..next])[..]).expect("convert bytes to field element error"));
        index = next;
    }
    field_elements
}