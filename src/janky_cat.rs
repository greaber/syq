use anyhow::{bail, Result};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

const CHUNK_SIZES: [usize; 8] = [1, 3, 1, 2, 5, 1, 8, 2];
const PAUSE_MILLIS: [u64; 8] = [80, 25, 140, 45, 10, 110, 30, 175];

enum CopyError {
    Read(io::Error),
    Write(io::Error),
}

struct Pace {
    step: usize,
}

impl Pace {
    fn new() -> Self {
        Self { step: 0 }
    }

    fn chunk_size(&self) -> usize {
        CHUNK_SIZES[self.step % CHUNK_SIZES.len()]
    }

    fn stumble(&mut self) {
        std::thread::sleep(Duration::from_millis(
            PAUSE_MILLIS[self.step % PAUSE_MILLIS.len()],
        ));
        self.step += 1;
    }
}

fn copy_slowly(
    input: &mut dyn Read,
    output: &mut dyn Write,
    pace: &mut Pace,
) -> std::result::Result<(), CopyError> {
    let mut buffer = [0_u8; 8];
    loop {
        let count = input
            .read(&mut buffer[..pace.chunk_size()])
            .map_err(CopyError::Read)?;
        if count == 0 {
            return Ok(());
        }
        output
            .write_all(&buffer[..count])
            .and_then(|()| output.flush())
            .map_err(CopyError::Write)?;
        pace.stumble();
    }
}

fn copy_one(
    input: &mut dyn Read,
    label: &OsStr,
    output: &mut dyn Write,
    pace: &mut Pace,
) -> Result<bool> {
    match copy_slowly(input, output, pace) {
        Ok(()) => Ok(true),
        Err(CopyError::Read(error)) => {
            crate::output::diagnostic!("syq cat: {}: {error}", Path::new(label).display());
            Ok(false)
        }
        Err(CopyError::Write(error)) => bail!("writing standard output: {error}"),
    }
}

pub fn run(arguments: &[OsString]) -> Result<i32> {
    let mut operands = Vec::new();
    let mut options_ended = false;
    for argument in arguments {
        if !options_ended && argument == "--" {
            options_ended = true;
        } else if !options_ended
            && argument != "-"
            && argument.as_os_str().as_bytes().starts_with(b"-")
        {
            bail!(
                "unsupported option {:?}; this cat is not very capable",
                argument
            );
        } else {
            operands.push(argument.as_os_str());
        }
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut pace = Pace::new();
    let mut succeeded = true;

    if operands.is_empty() {
        succeeded &= copy_one(
            &mut stdin.lock(),
            OsStr::new("standard input"),
            &mut output,
            &mut pace,
        )?;
    } else {
        for operand in operands {
            if operand == "-" {
                succeeded &= copy_one(
                    &mut stdin.lock(),
                    OsStr::new("standard input"),
                    &mut output,
                    &mut pace,
                )?;
                continue;
            }
            match File::open(operand) {
                Ok(mut file) => {
                    succeeded &= copy_one(&mut file, operand, &mut output, &mut pace)?;
                }
                Err(error) => {
                    crate::output::diagnostic!(
                        "syq cat: {}: {error}",
                        Path::new(operand).display()
                    );
                    succeeded = false;
                }
            }
        }
    }

    Ok(if succeeded { 0 } else { 1 })
}
