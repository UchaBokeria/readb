use std::io::{self, Read, Write};
pub fn line(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut c = [0];
    loop {
        r.read_exact(&mut c)?;
        if c[0] == b'\n' {
            return Ok(out);
        }
        if out.len() == max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header_too_large",
            ));
        }
        out.push(c[0]);
    }
}
pub fn frame(w: &mut impl Write, tag: u8, data: &[u8]) -> io::Result<()> {
    if data.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame_too_large",
        ));
    }
    w.write_all(&[tag])?;
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}
pub fn read_frame(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut h = [0; 5];
    r.read_exact(&mut h)?;
    let n = u32::from_be_bytes(h[1..].try_into().unwrap()) as usize;
    if n > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame_too_large",
        ));
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b)?;
    Ok((h[0], b))
}

/// Metadata may exceed a single frame. Never emit a success terminator after a dropped payload.
pub fn message(w: &mut impl Write, tag: u8, data: &[u8]) -> io::Result<()> {
    for part in data.chunks(65536) {
        frame(w, tag, part)?;
    }
    Ok(())
}
