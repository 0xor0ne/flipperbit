# FlipperBit

`Flipperbit` generates multiple corrupted variants of an input file by
randomly flipping bits in selected byte ranges.

`Flipperbit` allows to specify multiple byte ranges and the bit flipping
probabilty.

The output of `flipperbit` can be used as input to software (E.g., bulk file
processing applications, file parsing utilities) as a form of dumb fuzzing.

## Installing

Install `flipperbit` using cargo:

```bash
cargo install flipperbit
```

## Building

Clone the repository and build `flipperbit` with:

```bash
git clone https://github.com/0xor0ne/flipperbit && cd flipperbit
cargo build --release
```

`flipperbit` built executable is located in `./target/release/flipperbit`.

## Usage

Here is the `help` message of `flipperbit`:

```bash
>>> ./target/release/flipperbit -h
flipperbit 0.1.0
0xor0ne
Corrupted files generator. Random bits flipper.

USAGE:
    flipperbit [OPTIONS] --infile <INFILE> --outdir <OUTDIR>

OPTIONS:
        --fprob <FPROB>      Probability of flipping a bit [default: 0.2]
    -h, --help               Print help information
        --infile <INFILE>    Original file
        --nflips <NFLIPS>    Probability of flipping a bit [default: 1]
        --outdir <OUTDIR>    Output directory where the corrupted files will be saved
        --range <RANGES>     Bytes range to corrupt. E.g., '4,30', '4,' or ',30'
    -V, --version            Print version information
```

* `--infile`: (mandatory) path to the original file whose content will be
  randomly corrupted for each output file generated.
* `--outdir`: (mandatory) output directory where the corrupted files generated
  by `flipperbit` will be saved.
* `--nflips`: (optional) number of corrupted file variants to generate. By
  default only 1 output file is generated.
* `--fprob`: (optional) probability of flipping a single bit. By default 0.2.
* `--range`: range of bytes to corrupt (bytes are 0-based indexed). Every bit in
  the range has a probability of `--fprob` to be flipped. This option can be
  specified multiple times for defining different byte ranges. A range is
  specified as two comma separated integers (e.g., "4,63"). The first value in
  the range must be lower or equal to the second. `flipperbit` will corrupt
  bytes from the first value in the range up to the second value included. If
  the first value is not specified (e.g., ",63") `flipperbit` assumes 0. If the
  second value is not specified (e.g., "4,") `flipperbit` assumes input file
  size minus 1.

NOTE: the files generate by `flipperbit` and saved in `--outdir` will be named
as `<idx>_<input_file_name>` where `idx` goes from 0 to `--nflips` - 1. Files
with the same name already existing in `--outdir` will be overwritten.

## Examples

### ELF file corruption

The following example (assuming Linux) shows hot to generate 10000 corrupted
version of /bin/ls (ELF file). The 10000 corrupted ELF files are saved in
`/tmp/elf_ls_corrupted`. This particular example generates ELF files with a
corrupted header. The specified byte range skips the first 24 bytes in order to
avoid corrupting the header fields `e_ident`, `e_type`, `e_machine` and
`e_version`.

```bash
flipperit --infile /bin/ls \
  --outdir /tmp/elf_ls_corrupted \
  --range "24,63" \
  --fprob 0.05 \
  --nflips 10000
```

The output of `file` command on the generated ELFs shows that they are indeed
corrupted:

```bash
>>> file /tmp/elf_ls_corrupted/*
...
/tmp/elf_ls_corrupted/1004_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), corrupted program header size, corrupted section header size
/tmp/elf_ls_corrupted/1005_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), corrupted program header size, missing section headers at 72057594039114192
/tmp/elf_ls_corrupted/1006_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), too many program (8207)
/tmp/elf_ls_corrupted/1007_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), can't read elf program headers at 3298535161936, missing section headers at 19140302778533328
/tmp/elf_ls_corrupted/1008_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), corrupted program header size, corrupted section header size
/tmp/elf_ls_corrupted/1009_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), can't read elf program headers at 81065892804296768, corrupted section header size
/tmp/elf_ls_corrupted/100_ls:  ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), corrupted program header size, corrupted section header size
/tmp/elf_ls_corrupted/1010_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), corrupted program header size, missing section headers at 15764797720238800
/tmp/elf_ls_corrupted/1011_ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), too many program (16429)
...
```

In the second example instead we corrupt only the 18-th and the 19-th byte which
correspond to the field `e_machine` in the ELF header.

```bash
flipperit --infile /bin/ls \
  --outdir /tmp/elf_ls_corrupted \
  --range "18,19" \
  --fprob 0.3 \
  --nflips 10000
```

the output of `file` command shows that the "ELF architecture" is a random
different values in each of the generated output file:

```bash
>>> file /tmp/elf_ls_corrupted/*
...
/tmp/elf_ls_corrupted/1001_ls: ELF 64-bit LSB pie executable, *unknown arch 0xffff8e36* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1002_ls: ELF 64-bit LSB pie executable, *unknown arch 0x5033* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1003_ls: ELF 64-bit LSB pie executable, *unknown arch 0x401a* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1004_ls: ELF 64-bit LSB pie executable, *unknown arch 0x4c2a* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1005_ls: ELF 64-bit LSB pie executable, *unknown arch 0x409a* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1006_ls: ELF 64-bit LSB pie executable, *unknown arch 0xffff8c5c* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1007_ls: ELF 64-bit LSB pie executable, *unknown arch 0xcd* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1008_ls: ELF 64-bit LSB pie executable, *unknown arch 0x863* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1009_ls: ELF 64-bit LSB pie executable, *unknown arch 0x226e* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/100_ls:  ELF 64-bit LSB pie executable, *unknown arch 0x293e* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1010_ls: ELF 64-bit LSB pie executable, *unknown arch 0x5ab6* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1011_ls: ELF 64-bit LSB pie executable, *unknown arch 0x1225* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
/tmp/elf_ls_corrupted/1012_ls: ELF 64-bit LSB pie executable, *unknown arch 0xffffb076* version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6193e7eab54665ca319fbbf164b4e40abdab62bc, for GNU/Linux 4.4.0, stripped
...
```

### PCAP file corruption

This example shows how to use `flipperbit` to generrate corrupted `pcap` files.
In this particular case the range `"20,20"` is used. This means that only the
20-th byte of the input file is randomly corrupted. The 20-th byte in the `pcap`
file corresponds to the least significant byte of the Data Link Type field.

```bash
wget https://www.malware-traffic-analysis.net/2022/05/10/2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap.zip
unzip -Pinfected 2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap.zip
flipperit --infile 2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap \
  --outdir /tmp/pcap_corrupted \
  --range "20,20" \
  --fprob 0.5 \
  --nflips 256
```

the output of `tcpdump` shows that the data link type is indeed randomized:

```bash
>>> find /tmp/pcap_corrupted -type f -exec tcpdump -nn -c1 -r {} \;
...
reading from file /tmp/pcap_corrupted/112_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type ARCNET_LINUX (Linux ARCNET), snapshot length 65535
reading from file /tmp/pcap_corrupted/111_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type NULL (BSD loopback), snapshot length 65535
reading from file /tmp/pcap_corrupted/110_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type 5, snapshot length 65535
tcpdump: unknown data link type 5
reading from file /tmp/pcap_corrupted/109_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type ARCNET_LINUX (Linux ARCNET), snapshot length 65535
reading from file /tmp/pcap_corrupted/108_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type EN10MB (Ethernet), snapshot length 65535
reading from file /tmp/pcap_corrupted/107_2022-05-10-Contact-Forms-IcedID-infection-with-Cobalt-Strike.pcap, link-type 5, snapshot length 65535
...
```

## TODO

- Improve performance by making files creation async.

## References

- [Fuzzing Radare2 For 0days In About 30 Lines Of Code](https://tmpout.sh/1/5.html).

