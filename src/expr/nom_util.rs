//! Copied from nom::util so as to use CompleteStr, as the utilities
//! accept `&[u8]` and converting sucks.

use nom::Context;
use nom::ErrorKind;
use nom::types::CompleteStr;

pub fn prepare_errors<E: Clone>(
    input: &str,
    e: Context<CompleteStr, E>,
) -> Vec<(ErrorKind<E>, usize, usize)> {
    let mut v: Vec<(ErrorKind<E>, usize, usize)> = Vec::new();

    match e {
        Context::Code(p, kind) => {
            let (o1, o2) = slice_to_offsets(input, p.0);
            v.push((kind, o1, o2));
        }
        Context::List(mut l) => {
            for (p, kind) in l.drain(..) {
                let (o1, o2) = slice_to_offsets(input, p.0);
                v.push((kind, o1, o2));
            }

            v.reverse()
        }
    }

    v.sort_by(|a, b| a.1.cmp(&b.1));
    v
}

pub fn slice_to_offsets(input: &str, s: &str) -> (usize, usize) {
    let start = input.as_ptr();
    let off1 = s.as_ptr() as usize - start as usize;
    let off2 = off1 + s.len();
    (off1, off2)
}
