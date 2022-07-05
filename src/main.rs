//
// flipperbit
// Copyright (C) 2022  0xor0ne
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
//

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;

#[cfg(target_os = "linux")]
#[cfg(not(debug_assertions))]
#[cfg(feature="debugoff")]
use debugoff;

/// Randomly flip bits in ranges of bytes in a buffer (Vec<u8>).
mod flipperbit {
    use rand::prelude::*;
    use simple_error::SimpleError;

    /// Defines a range of bits that could be flipped
    #[derive(Debug)]
    pub struct FBRange {
        idx_min: usize,
        idx_max: usize,
    }

    pub struct FlipperBit {
        orig_buf: Vec<u8>,
        mod_buf: Vec<u8>,
        buf_len: usize,
        bits_n: usize,

        bit_flip_prob: f64,

        ranges: Vec<FBRange>,
    }

    impl FlipperBit {
        /// Create a FlipperBit
        ///
        /// # Args
        ///
        /// * `buf` - Original buffer
        /// * `bit_flip_prob` - Probability of flipping a bit, must be 0<=x<=1
        /// * `ranges` - ranges of bits to flip
        pub fn new(buf: Vec<u8>, bit_flip_prob: f64, ranges: Vec<FBRange>) -> Self {
            let buf_len: usize = buf.len();
            let bfp = if bit_flip_prob < 0.0 {
                0.0
            } else if bit_flip_prob > 1.0 {
                1.0
            } else {
                bit_flip_prob
            };

            if buf_len == 0 {
                panic!("Cannot create a FlipperBit of an empry buffer!");
            }

            for FBRange { idx_min, idx_max } in &ranges {
                if (*idx_min >= buf_len) || (*idx_max >= buf_len) {
                    panic!(
                        "{}",
                        format!(
                            "Invalid range ({}, {}), buf length {}",
                            *idx_min, *idx_max, buf_len
                        )
                    );
                }
            }

            FlipperBit {
                mod_buf: buf.clone(),
                orig_buf: buf,
                buf_len,
                bits_n: buf_len.checked_mul(8).unwrap(),
                bit_flip_prob: bfp,
                ranges,
            }
        }

        /// Return the buffer with flipped bits
        #[allow(dead_code)]
        pub fn get_flipped_buf(&self) -> &Vec<u8> {
            &self.mod_buf
        }

        /// Flip a single bit
        ///
        /// # Args
        ///
        /// * `idx` - index (zero based) of bit to flip
        #[allow(dead_code)]
        fn flip_bit(&mut self, idx: usize) -> Result<(), SimpleError> {
            if idx >= self.bits_n {
                Err(SimpleError::new(format!(
                    "Bit index ({}) >= {}",
                    idx, self.bits_n
                )))
            } else {
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                let mask = (1 as u8) << bit_idx;
                let b = self.mod_buf[byte_idx];

                self.mod_buf[byte_idx] = b ^ mask;

                Ok(())
            }
        }

        /// Flip the bits in `byte_idx`-th bytes in the buffer.
        /// Each bit has a probability `bit_flip_prob` to be flipped.
        fn flip_bits_in_byte_with_probability(&mut self, byte_idx: usize) {
            if byte_idx >= self.buf_len {
                panic!(
                    "{}",
                    format!("Byte index ({}) > buf length ({})", byte_idx, self.buf_len)
                );
            }

            let mut mask = 0x00;
            let mut rng = rand::thread_rng();

            for i in 0..8 {
                if rng.gen::<f64>() <= self.bit_flip_prob {
                    mask = mask | (1 << i);
                }
            }

            self.mod_buf[byte_idx] ^= mask;
        }

        /// Generate a new flipped buffer
        pub fn flip(&mut self) -> &Vec<u8> {
            self.mod_buf = self.orig_buf.clone();

            for i in 0..self.ranges.len() {
                let FBRange { idx_min, idx_max } = self.ranges[i];
                for idx in idx_min..=idx_max {
                    self.flip_bits_in_byte_with_probability(idx);
                }
            }

            &self.mod_buf
        }
    }

    impl FBRange {
        /// Byte range for FlipperBit
        ///
        /// # Args
        ///
        /// * `idx_min: index of the lower bytes
        /// * `idx_max: index of the highest bytes
        ///
        /// `idx_min` must be less or equal to `idx_max`.
        /// Byte `idx_max` is included in the range.
        pub fn new(idx_min: usize, idx_max: usize) -> Self {
            if idx_min > idx_max {
                panic!("idx_min cannot be > than idx_max");
            }

            FBRange { idx_min, idx_max }
        }

        pub fn get_idx_min(&self) -> usize {
            self.idx_min
        }

        pub fn get_idx_max(&self) -> usize {
            self.idx_max
        }

        #[allow(dead_code)]
        pub fn get_indexes(&self) -> (usize, usize) {
            (self.idx_min, self.idx_max)
        }

        pub fn set_idx_min(&mut self, idx_min: usize) {
            self.idx_min = idx_min;
        }

        pub fn set_idx_max(&mut self, idx_max: usize) {
            self.idx_max = idx_max;
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn bit_flit_0() {
            let buf = vec![0x00, 0x00];
            let rv = vec![super::FBRange::new(0, buf.len() - 1)];
            let mut fb = super::FlipperBit::new(buf, 0.5, rv);
            fb.flip_bit(0).unwrap();
            let mod_buf = fb.get_flipped_buf().clone();
            assert_eq!(mod_buf, vec![0x01, 0x00]);
        }

        #[test]
        fn bit_flit_10() {
            let buf = vec![0x00, 0x00];
            let rv = vec![super::FBRange::new(0, buf.len() - 1)];
            let mut fb = super::FlipperBit::new(buf, 0.5, rv);
            fb.flip_bit(10).unwrap();
            let mod_buf = fb.get_flipped_buf().clone();
            assert_eq!(mod_buf, vec![0x00, 0x04]);
        }

        #[test]
        fn bit_flit_0_and_10() {
            let buf = vec![0x00, 0x00];
            let rv = vec![super::FBRange::new(0, buf.len() - 1)];
            let mut fb = super::FlipperBit::new(buf, 0.5, rv);
            fb.flip_bit(0).unwrap();
            fb.flip_bit(10).unwrap();
            let mod_buf = fb.get_flipped_buf().clone();
            assert_eq!(mod_buf, vec![0x01, 0x04]);
        }

        #[test]
        fn bit_flit_error() {
            let buf = vec![0x00, 0x00];
            let rv = vec![super::FBRange::new(0, buf.len() - 1)];
            let mut fb = super::FlipperBit::new(buf, 0.5, rv);
            assert_eq!(false, fb.flip_bit(16).is_ok());
        }
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, required = true, help = "Original file")]
    infile: Option<std::path::PathBuf>,

    #[clap(
        long,
        required = true,
        help = "Output directory where the corrupted files will be saved"
    )]
    outdir: Option<std::path::PathBuf>,

    #[clap(long, default_value_t = 0.2,help = "Probability of flipping a bit")]
    fprob: f64,

    #[clap(long, default_value_t = 1, help = "Probability of flipping a bit")]
    nflips: usize,

    #[clap(long = "range", parse(try_from_str = parse_range), multiple_occurrences(true),
           help = "Bytes range to corrupt. E.g., '4,30', '4,' or ',30'")]
    ranges: Vec<flipperbit::FBRange>,
}

fn parse_range(s: &str) -> Result<flipperbit::FBRange, Box<dyn Error + Send + Sync + 'static>> {
    let ps: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    let pos = ps
        .find(',')
        .ok_or_else(|| format!("invalid range: no `,` found in `{}`", ps))?;

    let min = match ps[..pos].parse() {
        Ok(val) => val,
        _ => 0,
    };

    let max = match ps[pos + 1..].parse() {
        Ok(val) => val,
        _ => std::usize::MAX,
    };

    Ok(flipperbit::FBRange::new(min, max))
}

fn main() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    #[cfg(not(debug_assertions))]
    #[cfg(feature="debugoff")]
    debugoff::multi_ptraceme_or_die();

    let args = Args::parse();
    let infile = args.infile.unwrap();
    let outdir = args.outdir.unwrap();
    let fprob = args.fprob;
    let nflips = args.nflips;
    let mut ranges = args.ranges;

    // Create outdir if it does not exist
    if !Path::new(&outdir).exists() {
        println!("Creating output directory {}", outdir.to_str().unwrap());
        if let Err(error) = std::fs::create_dir(&outdir) {
            panic!(
                "Error creating directory {}: {}",
                outdir.to_str().unwrap(),
                error
            );
        }
    }

    // Open file and retrieve file len
    let mut f = match File::open(&infile) {
        Ok(file) => file,
        Err(error) => {
            panic!("Error opening file {}: {}", infile.to_str().unwrap(), error);
        }
    };

    let file_size: usize = f.metadata().unwrap().len() as usize;

    #[cfg(target_os = "linux")]
    #[cfg(not(debug_assertions))]
    #[cfg(feature="debugoff")]
    debugoff::multi_ptraceme_or_die();

    println!(
        "Original file: {} (size: {})",
        infile.to_str().unwrap(),
        file_size
    );
    println!("Output directory: {}", outdir.to_str().unwrap());
    println!("Bit flip Probability: {}", fprob);
    println!("N. flips: {}", nflips);

    // Normalize ranges
    // If idx_min is >= file_size, set both idx_min and idx_max to file_size - 1
    // if idx_max >= file_size, set idx_max to file_size - 1
    print!("Range:");
    if ranges.is_empty() {
        ranges.push(flipperbit::FBRange::new(0, file_size - 1));
    }

    for r in &mut ranges {
        if r.get_idx_min() >= file_size {
            r.set_idx_min(file_size - 1);
            r.set_idx_max(file_size - 1);
        }

        if r.get_idx_max() >= file_size {
            r.set_idx_max(file_size - 1);
        }

        print!(" ({}, {})", r.get_idx_min(), r.get_idx_max());
    }
    println!("");

    println!("Loading content of file {}", infile.to_str().unwrap());

    let mut f_buffer = Vec::new();
    f.read_to_end(&mut f_buffer)?;

    let mut fb = flipperbit::FlipperBit::new(f_buffer.clone(), fprob, ranges);

    let infile_name = infile.file_name().unwrap().to_str().unwrap();
    for i in 0..nflips {
        print!("\r{}", i+1);
        let mod_buf = fb.flip();

        let new_file_name = format!("{}_{}", i, infile_name);
        let mut new_path: PathBuf = outdir.clone();
        new_path.push(new_file_name);

        let mut new_file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&new_path)
        {
            Ok(file) => file,
            Err(error) => {
                panic!(
                    "Error creating file {}: {}",
                    new_path.to_str().unwrap(),
                    error
                );
            }
        };

        if let Err(error) = new_file.write_all(&mod_buf) {
            panic!(
                "Error writing to file {}: {}",
                new_path.to_str().unwrap(),
                error
            );
        }
    }
    println!("");

    Ok(())
}
