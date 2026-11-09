use crate::prelude::*;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;

use tokio::io::AsyncReadExt as _;

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold this guard across loading, modifying, and saving the database.
    /// The sibling lock file must remain in place when the database is replaced
    /// or removed, so every process locks the same inode.
    pub fn lock(server: &str, email: &str) -> Result<std::fs::File> {
        let file = crate::dirs::db_file(server, email);
        lock_file(&file).map_err(|source| Error::SaveDb { source, file })
    }

    pub async fn lock_async(
        server: &str,
        email: &str,
    ) -> Result<std::fs::File> {
        let file = crate::dirs::db_file(server, email);
        let path = file.clone();
        tokio::task::spawn_blocking(move || lock_file(&path))
            .await
            .map_err(|source| Error::SaveDb {
                source: std::io::Error::other(source),
                file: file.clone(),
            })?
            .map_err(|source| Error::SaveDb { source, file })
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json =
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?;
        save_bytes(&file, &json)
    }

    pub async fn save_async(
        &self,
        server: &str,
        email: &str,
        guard: &std::fs::File,
    ) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json =
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?;
        let path = file.clone();
        // A cancelled async caller must not release the transaction lock while
        // its blocking write is still in flight.
        let guard =
            guard.try_clone().map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            save_bytes(&path, &json)
        })
        .await
        .map_err(|source| Error::SaveDbAsync {
            source: std::io::Error::other(source),
            file: file.clone(),
        })?
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let _guard = Self::lock(server, email)?;
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}

fn lock_file(file: &std::path::Path) -> std::io::Result<std::fs::File> {
    // Database paths always include their containing directory.
    std::fs::create_dir_all(file.parent().unwrap())?;
    let mut lock_path = file.as_os_str().to_os_string();
    lock_path.push(".lock");
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)?;
    rustix::fs::flock(&guard, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(guard)
}

fn save_bytes(file: &std::path::Path, json: &[u8]) -> Result<()> {
    // Database paths always include their containing directory.
    let directory = file.parent().unwrap();
    (|| -> std::io::Result<()> {
        std::fs::create_dir_all(directory)?;
        // NamedTempFile creates the file with mode 0600 on Unix.
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        temporary.write_all(json)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(file).map_err(|error| error.error)?;
        Ok(())
    })()
    .map_err(|source| Error::SaveDb {
        source,
        file: file.to_owned(),
    })?;
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| Error::SaveDbCommitted {
            source,
            file: file.to_owned(),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn atomic_save_keeps_existing_readers_and_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("db.json");
        save_bytes(&file, b"old").unwrap();
        let mut reader = std::fs::File::open(&file).unwrap();
        save_bytes(&file, b"new").unwrap();
        let mut old = String::new();
        reader.read_to_string(&mut old).unwrap();
        assert_eq!(old, "old");
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600,
        );
    }

    #[test]
    fn failed_save_leaves_destination_unchanged_and_cleans_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("db.json");
        std::fs::create_dir(&file).unwrap();
        assert!(save_bytes(&file, b"new").is_err());
        assert!(file.is_dir());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn lock_survives_database_replacement_and_removal() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("db.json");
        let guard = lock_file(&file).unwrap();
        save_bytes(&file, b"old").unwrap();
        save_bytes(&file, b"new").unwrap();
        std::fs::remove_file(&file).unwrap();
        let lock_path = directory.path().join("db.json.lock");
        let contender = std::fs::File::open(&lock_path).unwrap();
        assert_eq!(
            std::fs::metadata(lock_path).unwrap().permissions().mode()
                & 0o777,
            0o600,
        );
        assert_eq!(
            rustix::fs::flock(
                &contender,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ),
            Err(rustix::io::Errno::WOULDBLOCK),
        );
        let retained_guard = guard.try_clone().unwrap();
        drop(guard);
        assert_eq!(
            rustix::fs::flock(
                &contender,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ),
            Err(rustix::io::Errno::WOULDBLOCK),
        );
        drop(retained_guard);
        rustix::fs::flock(
            &contender,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
    }
}
