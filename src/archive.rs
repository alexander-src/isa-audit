use std::fmt;

pub const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";
pub const THIN_ARCHIVE_MAGIC: &[u8; 8] = b"!<thin>\n";
const MEMBER_HEADER_SIZE: usize = 60;
const HEADER_END_MAGIC: &[u8; 2] = b"\x60\n";

/// Errors produced while parsing a Unix `ar` (`.a`) static archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    TooSmall,
    InvalidMagic,
    ThinArchiveUnsupported,
    TruncatedHeader {
        offset: usize,
    },
    InvalidHeaderEnd {
        offset: usize,
    },
    InvalidMemberSize {
        offset: usize,
    },
    TruncatedMember {
        name: String,
        offset: usize,
        declared: usize,
        available: usize,
    },
    InvalidExtendedName {
        offset: usize,
    },
    BsdNameLengthExceedsSize {
        offset: usize,
        name_len: usize,
        member_size: usize,
    },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "file smaller than 8-byte ar archive header"),
            Self::InvalidMagic => write!(f, "invalid ar magic (expected '!<arch>\\n')"),
            Self::ThinArchiveUnsupported => {
                write!(f, "thin ar archives ('!<thin>\\n') are not supported")
            }
            Self::TruncatedHeader { offset } => {
                write!(f, "truncated 60-byte ar member header at offset 0x{offset:x}")
            }
            Self::InvalidHeaderEnd { offset } => {
                write!(f, "invalid ar member header terminator at offset 0x{offset:x}")
            }
            Self::InvalidMemberSize { offset } => {
                write!(f, "invalid decimal member size at offset 0x{offset:x}")
            }
            Self::TruncatedMember {
                name,
                offset,
                declared,
                available,
            } => write!(
                f,
                "archive member '{name}' at offset 0x{offset:x} declares {declared} bytes but only {available} remain"
            ),
            Self::InvalidExtendedName { offset } => {
                write!(f, "invalid GNU extended filename reference at offset 0x{offset:x}")
            }
            Self::BsdNameLengthExceedsSize {
                offset,
                name_len,
                member_size,
            } => write!(
                f,
                "BSD extended name length {name_len} exceeds member size {member_size} at offset 0x{offset:x}"
            ),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Returns true if `data` starts with a standard or thin Unix `ar` archive header.
pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(ARCHIVE_MAGIC) || data.starts_with(THIN_ARCHIVE_MAGIC)
}

/// A single regular member extracted from a Unix `ar` archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember<'a> {
    pub name: String,
    pub data: &'a [u8],
}

/// Parsed view over a Unix `ar` (`.a`) archive without copying member payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive<'a> {
    pub members: Vec<ArchiveMember<'a>>,
}

fn is_symbol_table_name(raw_trimmed: &str) -> bool {
    matches!(
        raw_trimmed,
        "/" | "/SYM64/" | "__.SYMDEF" | "__.SYMDEF SORTED" | "__.SYMDEF_64" | "__.SYMDEF_64 SORTED"
    )
}

fn resolve_gnu_extended_name(
    strtab: Option<&[u8]>,
    str_off: usize,
    header_off: usize,
) -> Result<String, ArchiveError> {
    let table = strtab.ok_or(ArchiveError::InvalidExtendedName { offset: header_off })?;
    if str_off >= table.len() {
        return Err(ArchiveError::InvalidExtendedName { offset: header_off });
    }
    let slice = &table[str_off..];
    let end = slice
        .iter()
        .position(|&b| b == b'/' || b == b'\n' || b == 0)
        .unwrap_or(slice.len());
    if end == 0 {
        return Err(ArchiveError::InvalidExtendedName { offset: header_off });
    }
    let name = std::str::from_utf8(&slice[..end])
        .map_err(|_| ArchiveError::InvalidExtendedName { offset: header_off })?
        .trim_end();
    if name.is_empty() {
        return Err(ArchiveError::InvalidExtendedName { offset: header_off });
    }
    Ok(name.to_string())
}

impl<'a> Archive<'a> {
    /// Parses a GNU or BSD Unix `ar` archive, skipping symbol tables and resolving extended names.
    pub fn parse(data: &'a [u8]) -> Result<Self, ArchiveError> {
        if data.len() < ARCHIVE_MAGIC.len() {
            return Err(ArchiveError::TooSmall);
        }
        if data.starts_with(THIN_ARCHIVE_MAGIC) {
            return Err(ArchiveError::ThinArchiveUnsupported);
        }
        if !data.starts_with(ARCHIVE_MAGIC) {
            return Err(ArchiveError::InvalidMagic);
        }

        let mut members = Vec::new();
        let mut gnu_strtab: Option<&'a [u8]> = None;
        let mut pos = ARCHIVE_MAGIC.len();

        while pos < data.len() {
            let header_off = pos;
            let header_end = pos
                .checked_add(MEMBER_HEADER_SIZE)
                .ok_or(ArchiveError::TruncatedHeader { offset: header_off })?;
            if header_end > data.len() {
                return Err(ArchiveError::TruncatedHeader { offset: header_off });
            }
            let header = &data[pos..header_end];
            if &header[58..60] != HEADER_END_MAGIC {
                return Err(ArchiveError::InvalidHeaderEnd { offset: header_off });
            }

            let raw_name = std::str::from_utf8(&header[0..16])
                .map_err(|_| ArchiveError::InvalidExtendedName { offset: header_off })?;
            let size_str = std::str::from_utf8(&header[48..58])
                .map_err(|_| ArchiveError::InvalidMemberSize { offset: header_off })?
                .trim();
            if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ArchiveError::InvalidMemberSize { offset: header_off });
            }
            let member_size = size_str
                .parse::<usize>()
                .map_err(|_| ArchiveError::InvalidMemberSize { offset: header_off })?;

            let payload_start = header_end;
            let available = data.len() - payload_start;
            let payload_end = payload_start.checked_add(member_size).ok_or_else(|| {
                ArchiveError::TruncatedMember {
                    name: raw_name.trim_end().to_string(),
                    offset: header_off,
                    declared: member_size,
                    available,
                }
            })?;
            if payload_end > data.len() {
                return Err(ArchiveError::TruncatedMember {
                    name: raw_name.trim_end().to_string(),
                    offset: header_off,
                    declared: member_size,
                    available,
                });
            }
            let payload = &data[payload_start..payload_end];

            pos = payload_end;
            if member_size % 2 == 1 && pos < data.len() {
                pos += 1;
            }

            let trimmed = raw_name.trim_end();
            if trimmed == "//" {
                gnu_strtab = Some(payload);
                continue;
            }
            if is_symbol_table_name(trimmed) {
                continue;
            }

            if let Some(len_str) = trimmed.strip_prefix("#1/") {
                let name_len = len_str
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ArchiveError::InvalidExtendedName { offset: header_off })?;
                if name_len > payload.len() {
                    return Err(ArchiveError::BsdNameLengthExceedsSize {
                        offset: header_off,
                        name_len,
                        member_size,
                    });
                }
                let name_bytes = &payload[..name_len];
                let nul_end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                let name = std::str::from_utf8(&name_bytes[..nul_end])
                    .map_err(|_| ArchiveError::InvalidExtendedName { offset: header_off })?
                    .trim_end()
                    .to_string();
                if name.is_empty() {
                    return Err(ArchiveError::InvalidExtendedName { offset: header_off });
                }
                if is_symbol_table_name(&name) {
                    continue;
                }
                members.push(ArchiveMember {
                    name,
                    data: &payload[name_len..],
                });
                continue;
            }

            let name = if let Some(off_str) = trimmed.strip_prefix('/') {
                let str_off = off_str
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ArchiveError::InvalidExtendedName { offset: header_off })?;
                resolve_gnu_extended_name(gnu_strtab, str_off, header_off)?
            } else {
                trimmed.strip_suffix('/').unwrap_or(trimmed).to_string()
            };

            members.push(ArchiveMember {
                name,
                data: payload,
            });
        }

        Ok(Self { members })
    }
}
