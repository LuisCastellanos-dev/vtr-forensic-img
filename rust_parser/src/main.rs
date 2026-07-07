/// vtr-forensic-img v0.1.0 — Rust binary parser
/// src/main.rs
///
/// RESPONSABILIDAD: leer bytes no confiables, producir JSON estructurado.
/// PRINCIPIO: cada campo refleja bytes reales o está ausente.
/// La diferencia entre "no encontrado" y "valor vacío" es forense.

use md5::Md5;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

#[derive(Serialize, Default)]
struct ParsedImage {
    file_path: String,
    file_format: Option<String>,
    file_size_bytes: u64,
    hashes: Hashes,
    jpeg: Option<JpegInfo>,
    png: Option<PngInfo>,
    anomalies: Vec<Anomaly>,
    parse_warnings: Vec<String>,
    parser_version: &'static str,
}

#[derive(Serialize, Default)]
struct Hashes {
    sha256: Option<String>,
    md5: Option<String>,
}

#[derive(Serialize)]
struct JpegInfo {
    markers_found: Vec<JpegMarker>,
    has_exif_segment: bool,
    exif_offset: Option<u64>,
    exif_length: Option<u32>,
    has_xmp_segment: bool,
    comment_segments: Vec<CommentSegment>,
    trailing_bytes: u64,
}

#[derive(Serialize)]
struct JpegMarker {
    marker: String,
    offset: u64,
    declared_length: Option<u32>,
    actual_bytes_available: Option<u32>,
    truncated: bool,
}

#[derive(Serialize)]
struct CommentSegment {
    offset: u64,
    length: u32,
    content_preview: String,
    total_bytes: u32,
}

#[derive(Serialize)]
struct PngInfo {
    chunks: Vec<PngChunk>,
    has_iend: bool,
    post_iend_bytes: u64,
}

#[derive(Serialize)]
struct PngChunk {
    chunk_type: String,
    offset: u64,
    declared_length: u32,
    declared_crc: u32,
    computed_crc: Option<u32>,
    crc_valid: Option<bool>,
    text_content: Option<TextChunkContent>,
    truncated: bool,
}

#[derive(Serialize)]
struct TextChunkContent {
    key: String,
    value: Option<String>,
    value_original_len: usize,
    encoding: &'static str,
}

#[derive(Serialize)]
struct Anomaly {
    severity: &'static str,
    category: &'static str,
    description: String,
    byte_offset: Option<u64>,
}

const MAX_TEXT_FIELD: usize = 2048;
const MAX_CHUNK_SIZE: u32 = 32 * 1024 * 1024;
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

fn sanitize_bytes(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().min(MAX_TEXT_FIELD));
    for &b in data.iter().take(MAX_TEXT_FIELD) {
        if b.is_ascii_graphic() || b == b' ' {
            result.push(b as char);
        } else {
            result.push_str(&format!("\\x{:02x}", b));
        }
    }
    if data.len() > MAX_TEXT_FIELD {
        result.push_str(&format!("...[+{} bytes]", data.len() - MAX_TEXT_FIELD));
    }
    result
}

fn read_exact(reader: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn compute_hashes(path: &Path) -> Result<Hashes, String> {
    let file = File::open(path).map_err(|e| format!("open: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut sha = Sha256::new();
    let mut md = Md5::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {}", e))?;
        if n == 0 { break; }
        sha.update(&buf[..n]);
        md.update(&buf[..n]);
    }
    Ok(Hashes {
        sha256: Some(format!("{:x}", sha.finalize())),
        md5: Some(format!("{:x}", md.finalize())),
    })
}

fn detect_format(path: &Path) -> Option<&'static str> {
    let mut f = File::open(path).ok()?;
    let mut sig = [0u8; 12];
    let n = f.read(&mut sig).ok()?;
    if n < 2 { return None; }
    match &sig[..n.min(8)] {
        s if s.starts_with(b"\xFF\xD8\xFF") => Some("JPEG"),
        s if s.starts_with(b"\x89PNG\r\n\x1a\n") => Some("PNG"),
        s if s.starts_with(b"GIF87a") || s.starts_with(b"GIF89a") => Some("GIF"),
        s if s.starts_with(b"RIFF") && n >= 12 && &sig[8..12] == b"WEBP" => Some("WEBP"),
        s if s.starts_with(b"II\x2A\x00") || s.starts_with(b"MM\x00\x2A") => Some("TIFF"),
        _ => None,
    }
}

fn jpeg_marker_name(m: u8) -> &'static str {
    match m {
        0xD8 => "SOI", 0xD9 => "EOI", 0xC0 => "SOF0", 0xC1 => "SOF1",
        0xC2 => "SOF2", 0xC4 => "DHT", 0xDA => "SOS", 0xDB => "DQT",
        0xDD => "DRI", 0xE0 => "APP0", 0xE1 => "APP1", 0xE2 => "APP2",
        0xFE => "COM", 0xD0..=0xD7 => "RSTn", 0xE3..=0xEF => "APPn",
        _ => "UNK",
    }
}

fn parse_jpeg(path: &Path, result: &mut ParsedImage) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => { result.parse_warnings.push(format!("JPEG open: {}", e)); return; }
    };
    let mut reader = BufReader::new(file);
    let mut offset: u64 = 0;
    let mut markers_found = Vec::new();
    let mut has_exif_segment = false;
    let mut exif_offset = None;
    let mut exif_length = None;
    let mut has_xmp_segment = false;
    let mut comment_segments = Vec::new();

    let soi = match read_exact(&mut reader, 2) {
        Ok(b) => b,
        Err(_) => { result.parse_warnings.push("JPEG: demasiado corto para SOI".into()); return; }
    };
    if soi[0] != 0xFF || soi[1] != 0xD8 {
        result.parse_warnings.push(format!(
            "JPEG: SOI esperado 0xFFD8, encontrado 0x{:02X}{:02X}", soi[0], soi[1]
        ));
        return;
    }
    markers_found.push(JpegMarker { marker: "SOI".into(), offset: 0,
        declared_length: None, actual_bytes_available: None, truncated: false });
    offset += 2;
    let mut last_end: u64 = 2;

    loop {
        let mb = match read_exact(&mut reader, 2) {
            Ok(b) => b,
            Err(_) => break,
        };
        if mb[0] != 0xFF {
            result.anomalies.push(Anomaly {
                severity: "HIGH", category: "JPEG_STRUCTURE",
                description: format!("0xFF esperado en offset {}, encontrado 0x{:02X}", offset, mb[0]),
                byte_offset: Some(offset),
            });
            break;
        }
        let mtype = mb[1];
        let mname = jpeg_marker_name(mtype);
        let moffset = offset;
        offset += 2;

        // Markers sin datos
        if mtype == 0xD8 || mtype == 0xD9 || (0xD0..=0xD7).contains(&mtype) {
            let eoi = mtype == 0xD9;
            markers_found.push(JpegMarker { marker: mname.to_string(), offset: moffset,
                declared_length: None, actual_bytes_available: None, truncated: false });
            last_end = offset;
            if eoi { break; }
            continue;
        }

        let lb = match read_exact(&mut reader, 2) {
            Ok(b) => b,
            Err(_) => { result.parse_warnings.push(format!("JPEG: EOF al leer len de {}", mname)); break; }
        };
        let seg_len = u16::from_be_bytes([lb[0], lb[1]]) as u32;
        offset += 2;

        if seg_len < 2 {
            result.anomalies.push(Anomaly {
                severity: "HIGH", category: "JPEG_STRUCTURE",
                description: format!("Segmento {}: longitud {} < 2 — imposible", mname, seg_len),
                byte_offset: Some(moffset),
            });
            break;
        }

        let data_len = (seg_len - 2) as usize;
        let seg_data = match read_exact(&mut reader, data_len) {
            Ok(b) => b,
            Err(_) => {
                let avail = result.file_size_bytes.saturating_sub(offset) as u32;
                markers_found.push(JpegMarker { marker: mname.to_string(), offset: moffset,
                    declared_length: Some(seg_len), actual_bytes_available: Some(avail), truncated: true });
                result.parse_warnings.push(format!("JPEG: {} truncado — declarado {}, disponible ~{}", mname, data_len, avail));
                break;
            }
        };
        offset += data_len as u64;
        last_end = offset;

        // SOS (0xDA): el header tiene longitud declarada, pero el payload
        // de scan data NO — se extiende hasta el siguiente marker real.
        // Un marker real es 0xFF seguido de algo != 0x00 (byte stuffing) y != 0xFF.
        // Si no consumimos esto, last_end queda en el final del header SOS
        // y todo el scan data se reporta como "trailing bytes" — falso positivo.
        if mtype == 0xDA {
            let mut prev_was_ff = false;
            loop {
                let mut byte = [0u8; 1];
                match reader.read_exact(&mut byte) {
                    Err(_) => break,
                    Ok(_) => {}
                }
                offset += 1;
                if prev_was_ff && byte[0] != 0x00 && byte[0] != 0xFF {
                    // Encontramos un marker real — retroceder 2 bytes lógicamente
                    // (el 0xFF ya fue consumido, el tipo también)
                    // Guardamos el tipo para el siguiente ciclo del loop exterior
                    // Re-insertar en el stream no es posible con BufReader simple,
                    // así que registramos la posición y usamos el marker encontrado
                    // como si fuera el próximo ciclo del loop exterior.
                    last_end = offset - 2;
                    let next_marker_type = byte[0];
                    // Procesar este marker inline si es EOI, sino continuar
                    if next_marker_type == 0xD9 {
                        markers_found.push(JpegMarker {
                            marker: "EOI".to_string(),
                            offset: offset - 2,
                            declared_length: None,
                            actual_bytes_available: None,
                            truncated: false,
                        });
                        last_end = offset;
                    } else {
                        // Otro marker — el loop exterior no puede recuperarlo
                        // sin un peek/unread. Registramos que el scan terminó aquí.
                        result.parse_warnings.push(format!(
                            "JPEG: scan data terminado en offset 0x{:X}, siguiente marker 0x{:02X}",
                            last_end, next_marker_type
                        ));
                    }
                    break;
                }
                prev_was_ff = byte[0] == 0xFF;
            }
        }

        if mtype == 0xE1 {
            if seg_data.starts_with(b"Exif\0\0") {
                has_exif_segment = true;
                exif_offset = Some(moffset);
                exif_length = Some(seg_len);
            } else if seg_data.starts_with(b"http://ns.adobe.com/xap") || seg_data.starts_with(b"<?xpacket") {
                has_xmp_segment = true;
            }
        }
        if mtype == 0xFE {
            let total = data_len as u32;
            comment_segments.push(CommentSegment {
                offset: moffset, length: seg_len,
                content_preview: sanitize_bytes(&seg_data[..seg_data.len().min(512)]),
                total_bytes: total,
            });
        }

        markers_found.push(JpegMarker { marker: mname.to_string(), offset: moffset,
            declared_length: Some(seg_len), actual_bytes_available: Some(data_len as u32), truncated: false });
    }

    let trailing = result.file_size_bytes.saturating_sub(last_end);
    if trailing > 0 {
        result.anomalies.push(Anomaly {
            severity: "MEDIUM", category: "JPEG_TRAILING_DATA",
            description: format!("{} bytes tras el último marker JPEG — posible dato appended", trailing),
            byte_offset: Some(last_end),
        });
    }

    result.jpeg = Some(JpegInfo {
        markers_found, has_exif_segment, exif_offset, exif_length,
        has_xmp_segment, comment_segments, trailing_bytes: trailing,
    });
}

fn parse_png(path: &Path, result: &mut ParsedImage) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => { result.parse_warnings.push(format!("PNG open: {}", e)); return; }
    };
    let mut reader = BufReader::new(file);
    let mut offset: u64 = 0;
    let mut chunks = Vec::new();
    let mut has_iend = false;
    let mut post_iend_bytes: u64 = 0;

    let sig = match read_exact(&mut reader, 8) {
        Ok(b) => b,
        Err(_) => { result.parse_warnings.push("PNG: demasiado corto para firma".into()); return; }
    };
    if sig.as_slice() != PNG_SIGNATURE {
        result.parse_warnings.push(format!("PNG: firma inválida {:?}", sig));
        return;
    }
    offset += 8;

    loop {
        let header = match read_exact(&mut reader, 8) {
            Ok(b) => b,
            Err(_) => break,
        };

        // try_into() garantiza 4 bytes en tiempo de compilación
        let declared_length = u32::from_be_bytes(header[0..4].try_into().expect("4 bytes"));
        let type_bytes = &header[4..8];
        let chunk_type = String::from_utf8_lossy(type_bytes).to_string();
        let chunk_offset = offset;
        offset += 8;

        if declared_length > MAX_CHUNK_SIZE {
            result.anomalies.push(Anomaly {
                severity: "HIGH", category: "PNG_CHUNK_SIZE",
                description: format!("Chunk '{}' en {}: {} bytes — excede límite de seguridad", chunk_type, chunk_offset, declared_length),
                byte_offset: Some(chunk_offset),
            });
            let skip = declared_length as usize + 4;
            let mut buf = vec![0u8; 1024];
            let mut done = 0;
            while done < skip {
                let n = (skip - done).min(1024);
                match reader.read(&mut buf[..n]) { Ok(0) | Err(_) => break, Ok(k) => done += k, }
            }
            offset += done as u64;
            continue;
        }

        let chunk_data = if declared_length > 0 {
            match read_exact(&mut reader, declared_length as usize) {
                Ok(b) => b,
                Err(_) => {
                    let avail = result.file_size_bytes.saturating_sub(offset);
                    chunks.push(PngChunk {
                        chunk_type, offset: chunk_offset, declared_length,
                        declared_crc: 0, computed_crc: None, crc_valid: None,
                        text_content: None, truncated: true,
                    });
                    result.parse_warnings.push(format!("PNG chunk truncado en {}: declarado {} disponible ~{}", chunk_offset, declared_length, avail));
                    break;
                }
            }
        } else { Vec::new() };

        let crc_raw = match read_exact(&mut reader, 4) {
            Ok(b) => b,
            Err(_) => { result.parse_warnings.push(format!("PNG '{}': EOF antes de CRC", chunk_type)); break; }
        };
        let declared_crc = u32::from_be_bytes(crc_raw.try_into().expect("4 bytes"));
        offset += declared_length as u64 + 4;

        let computed_crc = {
            let mut h = crc32fast::Hasher::new();
            h.update(type_bytes);
            h.update(&chunk_data);
            h.finalize()
        };
        let crc_valid = computed_crc == declared_crc;

        if !crc_valid {
            result.anomalies.push(Anomaly {
                severity: "HIGH", category: "PNG_CRC_MISMATCH",
                description: format!("Chunk '{}' en {}: CRC declarado 0x{:08X} calculado 0x{:08X}", chunk_type, chunk_offset, declared_crc, computed_crc),
                byte_offset: Some(chunk_offset),
            });
        }

        let text_content = match chunk_type.as_str() {
            "tEXt" => parse_text_chunk(&chunk_data, "latin-1"),
            "iTXt" => parse_itext_chunk(&chunk_data),
            _ => None,
        };

        let is_iend = chunk_type == "IEND";
        chunks.push(PngChunk {
            chunk_type, offset: chunk_offset, declared_length,
            declared_crc, computed_crc: Some(computed_crc), crc_valid: Some(crc_valid),
            text_content, truncated: false,
        });

        if is_iend {
            has_iend = true;
            let mut rest = 0u64;
            let mut drain = [0u8; 4096];
            loop { match reader.read(&mut drain) { Ok(0) | Err(_) => break, Ok(n) => rest += n as u64, } }
            if rest > 0 {
                result.anomalies.push(Anomaly {
                    severity: "MEDIUM", category: "PNG_POST_IEND_DATA",
                    description: format!("{} bytes tras IEND — posibles datos ocultos o archivo concatenado", rest),
                    byte_offset: Some(offset),
                });
                post_iend_bytes = rest;
            }
            break;
        }
    }

    if !has_iend {
        result.anomalies.push(Anomaly {
            severity: "MEDIUM", category: "PNG_NO_IEND",
            description: "PNG sin chunk IEND — truncado o estructura inválida".into(),
            byte_offset: None,
        });
    }

    result.png = Some(PngInfo { chunks, has_iend, post_iend_bytes });
}

fn parse_text_chunk(data: &[u8], encoding: &'static str) -> Option<TextChunkContent> {
    let sep = data.iter().position(|&b| b == 0)?;
    let key = sanitize_bytes(&data[..sep]);
    let val_bytes = &data[sep + 1..];
    Some(TextChunkContent {
        key,
        value: if val_bytes.is_empty() { None } else { Some(sanitize_bytes(val_bytes)) },
        value_original_len: val_bytes.len(),
        encoding,
    })
}

fn parse_itext_chunk(data: &[u8]) -> Option<TextChunkContent> {
    let sep = data.iter().position(|&b| b == 0)?;
    let key = sanitize_bytes(&data[..sep]);
    let mut pos = sep + 3;
    while pos < data.len() && data[pos] != 0 { pos += 1; } pos += 1;
    while pos < data.len() && data[pos] != 0 { pos += 1; } pos += 1;
    let val_bytes = if pos < data.len() { &data[pos..] } else { &[] };
    Some(TextChunkContent {
        key,
        value: if val_bytes.is_empty() { None } else { Some(sanitize_bytes(val_bytes)) },
        value_original_len: val_bytes.len(),
        encoding: "utf-8",
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("uso: vtr_image_parser <ruta>");
        std::process::exit(1);
    }
    let path = Path::new(&args[1]);
    if !path.exists() {
        eprintln!("archivo no encontrado: {}", args[1]);
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut result = ParsedImage {
        file_path: args[1].clone(),
        file_size_bytes: file_size,
        parser_version: "0.1.0",
        ..Default::default()
    };

    result.file_format = detect_format(path).map(|s| s.to_string());

    match compute_hashes(path) {
        Ok(h) => result.hashes = h,
        Err(e) => result.parse_warnings.push(format!("hashes: {}", e)),
    }

    match result.file_format.as_deref() {
        Some("JPEG") => parse_jpeg(path, &mut result),
        Some("PNG") => parse_png(path, &mut result),
        Some(fmt) => result.parse_warnings.push(format!("formato '{}' sin parser específico en v0.1.0", fmt)),
        None => {
            result.anomalies.push(Anomaly {
                severity: "HIGH", category: "FORMAT_UNKNOWN",
                description: format!("Firma no reconocida en '{}'", args[1]),
                byte_offset: Some(0),
            });
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
            std::process::exit(2);
        }
    }

    match serde_json::to_string(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => { eprintln!("error serializando: {}", e); std::process::exit(1); }
    }
}
