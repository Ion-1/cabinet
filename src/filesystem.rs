use crate::PostData;
use async_lock::{
    Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};
use axum::http::StatusCode;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, UserAgent};
use axum_extra::TypedHeader;
use base64::prelude::BASE64_URL_SAFE;
use base64::Engine;
use jiff::Zoned;
use mime::Mime;
use rand::prelude::StdRng;
use rand::{RngCore, SeedableRng};
use sanitise_file_name::{sanitize_with_options, Options};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes, DisplayFromStr};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, instrument, trace, warn};
use xxhash_rust::xxh3::xxh3_128;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct UserToken(#[serde_as(as = "Bytes")] [u8; 32]);

impl UserToken {
    pub(crate) fn new(token: impl Into<[u8; 32]>) -> Self {
        Self(token.into())
    }
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 32];
        StdRng::from_os_rng().fill_bytes(&mut bytes);
        UserToken(bytes)
    }
}

impl FromStr for UserToken {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = BASE64_URL_SAFE.decode(s)?;
        match <[u8; 32]>::try_from(decoded) {
            Ok(arr) => Ok(Self(arr)),
            Err(v) => Err(base64::DecodeError::InvalidLength(v.len())),
        }
    }
}

impl TryFrom<TypedHeader<Authorization<Bearer>>> for UserToken {
    type Error = (StatusCode, Box<str>);

    fn try_from(value: TypedHeader<Authorization<Bearer>>) -> Result<Self, Self::Error> {
        match value.0.token().parse::<UserToken>() {
            Ok(t) => Ok(t),
            Err(_) => Err((StatusCode::UNAUTHORIZED, "Invalid token.".into())),
        }
    }
}
impl Display for UserToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE.encode(self.0))
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct XXH3_128Hash(#[serde_as(as = "Bytes")] pub(crate) [u8; 16]);

impl XXH3_128Hash {
    pub(crate) fn new(hash: impl Into<[u8; 16]>) -> Self {
        Self(hash.into())
    }
}

impl From<u128> for XXH3_128Hash {
    fn from(value: u128) -> Self {
        Self::new(value.to_be_bytes())
    }
}

impl XXH3_128Hash {
    pub(crate) fn calculate(value: &[u8]) -> Self {
        xxh3_128(value).into()
    }
}

impl FromStr for XXH3_128Hash {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = BASE64_URL_SAFE.decode(s)?;
        match <[u8; 16]>::try_from(decoded) {
            Ok(arr) => Ok(Self(arr)),
            Err(v) => Err(base64::DecodeError::InvalidLength(v.len())),
        }
    }
}

impl Display for XXH3_128Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE.encode(self.0))
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MetaFile {
    pub(crate) file_name: String, // Windows-safe file name sanitised from the form or slice of the hash
    pub(crate) file_size: usize,
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) uri_path: String,
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) mime_type: Mime,
    pub(crate) nsfw: bool,
    pub(crate) creation_date: Zoned,
    pub(crate) expiration_date: Zoned,
    pub(crate) restricted: bool,
    pub(crate) access_token: UserToken,
    pub(crate) hash: XXH3_128Hash,
    pub(crate) uploader_ua: String,
    pub(crate) uploader_ip: SocketAddr,
}

impl MetaFile {
    fn from_post(value: PostData) -> (Self, bool, XXH3_128Hash, Vec<u8>) {
        (
            Self {
                file_name: value.file_name,
                file_size: value.file_size,
                mime_type: value.file_mime,
                nsfw: value.nsfw,
                creation_date: value.creation_date,
                expiration_date: value.expiration_date,
                restricted: false,
                access_token: value.access_token,
                hash: value.file_hash.clone(),
                uploader_ua: value.uploader_ua,
                uploader_ip: value.uploader_ip,
                uri_path: "".parse().unwrap(),
            },
            value.secret,
            value.file_hash,
            value.file_data,
        )
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseData {
    blocklist_ip: HashSet<SocketAddr>,
    blocklist_ua: HashSet<String>,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    hashes_on_fs: HashMap<XXH3_128Hash, usize>,
    url_file_map: HashMap<String, MetaFile>,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    hash_file_map: HashMap<XXH3_128Hash, MetaFile>,
}

impl From<Database> for DatabaseData {
    fn from(value: Database) -> Self {
        Self {
            blocklist_ip: value.blocklist_ip.into_inner(),
            blocklist_ua: value.blocklist_ua.into_inner(),
            hashes_on_fs: value.hashes_on_fs.into_inner(),
            url_file_map: value.url_file_map.into_inner(),
            hash_file_map: value.hash_file_map.into_inner(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Database {
    path: PathBuf,
    blocklist_ip: RwLock<HashSet<SocketAddr>>,
    blocklist_ua: RwLock<HashSet<String>>,
    // File hashes on the fs to number of MetaFile referencing them
    // Restricted files will still be here, but their data will be null
    // on the fs
    // Any fs operations require a lock on the mutex
    // Locks are acquired in the order of: hash_file_map, url_file_map,
    // hashes_on_fs to prevent a deadlock
    hashes_on_fs: Mutex<HashMap<XXH3_128Hash, usize>>,
    // URL to file metadata
    url_file_map: RwLock<HashMap<String, MetaFile>>,
    // Hash to restricted files
    hash_file_map: RwLock<HashMap<XXH3_128Hash, MetaFile>>,
}

impl Database {
    fn from_data(value: DatabaseData, path: impl AsRef<Path>) -> Self {
        trace!("Constructing Database from data");
        Self {
            path: path.as_ref().to_path_buf(),
            blocklist_ip: RwLock::new(value.blocklist_ip),
            blocklist_ua: RwLock::new(value.blocklist_ua),
            hashes_on_fs: Mutex::new(value.hashes_on_fs),
            url_file_map: RwLock::new(value.url_file_map),
            hash_file_map: RwLock::new(value.hash_file_map),
        }
    }

    fn new(path: impl AsRef<Path>) -> Self {
        trace!("{:?} {}", path.as_ref(), "Initializing new Database");
        Self {
            path: path.as_ref().to_path_buf(),
            blocklist_ip: HashSet::new().into(),
            blocklist_ua: HashSet::new().into(),
            hashes_on_fs: HashMap::new().into(),
            url_file_map: HashMap::new().into(),
            hash_file_map: HashMap::new().into(),
        }
    }

    #[instrument(skip(path))]
    pub(crate) async fn open_from(path: impl AsRef<Path>) -> Result<Database, bson::error::Error> {
        let path = path.as_ref();
        trace!(?path, "Opening database from path");
        if !path.is_file() {
            debug!(?path, "No existing database file; creating new");
            let db = Database::new(path);
            let _ = db.save(None, None, None, None, None).await;
            return Ok(db);
        }
        let mut buf = Vec::new();
        File::open(path).await?.read_to_end(&mut buf).await?;
        debug!(size = buf.len(), ?path, "Loaded database file into memory");
        Ok(Database::from_data(
            bson::deserialize_from_slice::<DatabaseData>(&buf)?,
            path,
        ))
    }

    #[instrument(skip(self))]
    pub(crate) async fn consume_save(self) -> Result<(), bson::error::Error> {
        trace!("Consuming and saving database to disk");
        Ok(File::create(&self.path)
            .await?
            .write_all(&bson::serialize_to_vec(&DatabaseData::from(self))?)
            .await?)
    }

    #[instrument(skip(
        self,
        lock_ip,
        lock_ua,
        lock_hashes,
        lock_url_file_map,
        lock_hash_file_map
    ))]
    pub(crate) async fn save(
        &self,
        lock_ip: Option<RwLockReadGuard<'_, HashSet<SocketAddr>>>,
        lock_ua: Option<RwLockReadGuard<'_, HashSet<String>>>,
        lock_hashes: Option<MutexGuard<'_, HashMap<XXH3_128Hash, usize>>>,
        lock_url_file_map: Option<RwLockReadGuard<'_, HashMap<String, MetaFile>>>,
        lock_hash_file_map: Option<RwLockReadGuard<'_, HashMap<XXH3_128Hash, MetaFile>>>,
    ) -> Result<(), bson::error::Error> {
        trace!(path=?self.path, "Saving database snapshot at");
        Ok(File::create(&self.path)
            .await?
            .write_all(&bson::serialize_to_vec(&DatabaseData {
                blocklist_ip: match lock_ip {
                    Some(lock) => lock.clone(),
                    None => self.blocklist_ip.read().await.clone(),
                },
                blocklist_ua: match lock_ua {
                    Some(lock) => lock.clone(),
                    None => self.blocklist_ua.read().await.clone(),
                },
                hashes_on_fs: match lock_hashes {
                    Some(lock) => lock.clone(),
                    None => self.hashes_on_fs.lock().await.clone(),
                },
                url_file_map: match lock_url_file_map {
                    Some(lock) => lock.clone(),
                    None => self.url_file_map.read().await.clone(),
                },
                hash_file_map: match lock_hash_file_map {
                    Some(lock) => lock.clone(),
                    None => self.hash_file_map.read().await.clone(),
                },
            })?)
            .await?)
    }

    pub(crate) fn insert(&mut self, meta_file: MetaFile) {
        self.url_file_map
            .get_mut()
            .insert(meta_file.file_name.clone(), meta_file);
    }

    pub(crate) fn block_ip(&mut self, addr: SocketAddr) {
        self.blocklist_ip.get_mut().insert(addr);
    }

    pub(crate) fn block_ua(&mut self, ua: UserAgent) {
        self.blocklist_ua.get_mut().insert(ua.to_string());
    }

    pub(crate) async fn is_ip_blocked(&self, addr: &SocketAddr) -> bool {
        let blocked = self.blocklist_ip.read().await.contains(addr);
        debug!(ip = %addr, blocked = blocked, "Checked if IP is blocked");
        blocked
    }

    pub(crate) async fn is_ua_blocked(&self, ua: &UserAgent) -> bool {
        let blocked = self.blocklist_ua.read().await.contains(ua.as_str());
        debug!(ua = %ua.as_str(), blocked = blocked, "Checked if UA is blocked");
        blocked
    }

    /// Returns true if the hash was already present in the database
    pub(crate) fn insert_hash(&mut self, key: XXH3_128Hash) -> bool {
        trace!(hash = %key, "Inserting hash reference");
        match self.hashes_on_fs.get_mut().entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
                debug!(count = *entry.get(), "Incremented hash reference count");
                true
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(1);
                debug!("Inserted new hash reference with count 1");
                false
            }
        }
    }

    /// Returns true if the hash is still present in the database
    pub(crate) fn remove_hash(&mut self, key: XXH3_128Hash) -> bool {
        trace!(hash = %key, "Removing hash reference");
        if let Some(entry) = self.hashes_on_fs.get_mut().get_mut(&key)
            && *entry > 1
        {
            *entry -= 1;
            debug!(remaining = *entry, "Decremented hash reference count");
            return true;
        }
        self.hashes_on_fs.get_mut().remove(&key);
        debug!("Removed hash from map");
        false
    }
}

/// Filesystem that implements guards with an access token
/// Files are saved by their hash as name, for dedup purposes.
/// Users are provided with a unique URL and a token for management
pub(crate) struct LocalTokenizedFilesystem {
    dir: PathBuf,
    pub(crate) database: Database,
}

impl LocalTokenizedFilesystem {
    pub(crate) async fn new(dir: impl AsRef<Path>) -> Result<Self, bson::error::Error> {
        let dir = dir.as_ref();
        trace!(?dir, "Initializing LocalTokenizedFilesystem");
        if !dir.is_dir() & !std::fs::metadata(dir)?.permissions().readonly() {
            return Err(Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Only readonly access to dir {dir:?}"),
            )
            .into());
        }
        let db_path = dir.join(".database.bson");
        debug!(?db_path, "Opening database file");
        Ok(Self {
            dir: dir.to_path_buf(),
            database: Database::open_from(&db_path).await?,
        })
    }

    pub(crate) fn sanitize_file_name(name: &str) -> String {
        sanitize_with_options(
            name,
            &Options {
                windows_safe: true,
                ..Options::DEFAULT
            },
        )
    }
}

fn make_unique<T>(base: String, map: &HashMap<String, T>) -> String {
    if !map.contains_key(&base) {
        return base.to_string();
    }

    let mut counter: u64 = 1;
    loop {
        let candidate = format!("{}_{}", &base, counter);
        if !map.contains_key(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

#[derive(Debug)]
pub(crate) enum SaveError {
    FileRestricted,
    FileSystemError(Error),
}

impl From<Error> for SaveError {
    fn from(err: Error) -> Self {
        Self::FileSystemError(err)
    }
}

impl LocalTokenizedFilesystem {
    #[instrument(skip(self))]
    pub(crate) async fn get(&self, path: &str) -> io::Result<(File, MetaFile)> {
        trace!(%path, "Fetching file by URL path");
        let restricted_guard = self.database.hash_file_map.read().await;
        if let Some(meta_file) = self.database.url_file_map.read().await.get(path) {
            if restricted_guard.contains_key(&meta_file.hash) {
                self.database.url_file_map.write().await.remove(path);
                return Err(Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "File has been restricted.",
                ));
            }
            debug!(hash = %meta_file.hash, "Opening file by hash");
            let file = File::open(self.dir.join(meta_file.hash.to_string())).await?;
            Ok((file, meta_file.clone()))
        } else {
            debug!(%path, "File not found in url_file_map");
            Err(Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {path}"),
            ))
        }
    }

    #[instrument(skip(self, data), fields(file_name = %data.file_name, size = data.file_size))]
    pub(crate) async fn save(&self, data: PostData) -> Result<String, SaveError> {
        trace!("Saving new file");
        let (mut meta_file_uninit, secret, hash, file_data) = MetaFile::from_post(data);
        let restricted_shared_read_lock = self.database.hash_file_map.read().await;
        // We keep the restricted read lock to prevent the possibility of
        // our current hash being added without our MetaFile having been added
        if restricted_shared_read_lock.contains_key(&meta_file_uninit.hash) {
            warn!(hash = %meta_file_uninit.hash, "Attempt to save a restricted file");
            return Err(SaveError::FileRestricted);
        }
        let mut urlfilemap_write_lock = self.database.url_file_map.upgradable_read().await;
        let uri = if !secret {
            make_unique(
                form_urlencoded::byte_serialize(meta_file_uninit.file_name.as_bytes()).collect(),
                &urlfilemap_write_lock,
            )
        } else {
            let mut random = UserToken::generate().to_string();
            while urlfilemap_write_lock.contains_key(&random) {
                random = UserToken::generate().to_string();
            }
            random
        };
        debug!(%uri, secret = secret, "Determined URI for file");
        meta_file_uninit.uri_path = uri.clone();
        let mut urlfilemap_write_lock =
            RwLockUpgradableReadGuard::upgrade(urlfilemap_write_lock).await;
        urlfilemap_write_lock.insert(uri.clone(), meta_file_uninit);
        let mut hashes_mutex = self.database.hashes_on_fs.lock().await;
        match hashes_mutex.entry(hash.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
                debug!(hash = %hash, count = *entry.get(), "Incremented hash count");
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(1);
                debug!(hash = %hash, "Writing file to disk for first time");
                File::create_new(self.dir.join(hash.to_string()))
                    .await?
                    .write_all(&file_data)
                    .await?;
            }
        }
        debug!("Saving database!");
        // Since we hold all the locks, we might as well save the database
        if let Err(e) = self
            .database
            .save(
                None,
                None,
                Some(hashes_mutex),
                Some(RwLockWriteGuard::downgrade(urlfilemap_write_lock)),
                Some(restricted_shared_read_lock),
            )
            .await
        {
            debug!(err=%e, "Error saving database")
        }
        info!(uri = %uri, "Saved file");
        Ok(uri)
    }

    #[instrument(skip(self, credentials))]
    pub(crate) async fn remove_file(
        &self,
        path: &str,
        credentials: &UserToken,
    ) -> Result<(), DeletionError> {
        trace!(%path, "Removing file");
        let restricted_shared_read_lock = self.database.hash_file_map.read().await;
        let mut url_file_map_lock = self.database.url_file_map.write().await;
        if let std::collections::hash_map::Entry::Occupied(entry) =
            url_file_map_lock.entry(path.parse().unwrap())
        {
            let meta = entry.get();
            if meta.access_token != *credentials {
                warn!(path = %path, "Invalid credentials for delete");
                return Err(DeletionError::Forbidden);
            }
            let mut hash_mutex = self.database.hashes_on_fs.lock().await;
            match hash_mutex.get_mut(&meta.hash) {
                None => {
                    error!("Hash on fs and url_file_map are out of sync!");
                    panic!("Hash on fs and url_file_map are out of sync!")
                }
                Some(a) if *a > 1 => {
                    debug!(remaining = *a, "Decremented hash refs; not deleting data");
                    *a -= 1;
                    url_file_map_lock.remove(path);
                }
                Some(a) if *a == 1 => {
                    debug!(hash = %meta.hash, "Deleting data file from disk");
                    tokio::fs::remove_file(self.dir.join(meta.hash.to_string())).await?;
                    hash_mutex.remove(&meta.hash);
                    url_file_map_lock.remove(path);
                }
                Some(_) => {
                    error!("hashes_on_fs has invalid state");
                    panic!("Hash_on_fs has invalid state!")
                }
            }
            debug!("Saving database!");
            // Since we hold all the locks, we might as well save the database
            if let Err(e) = self
                .database
                .save(
                    None,
                    None,
                    Some(hash_mutex),
                    Some(RwLockWriteGuard::downgrade(url_file_map_lock)),
                    Some(restricted_shared_read_lock),
                )
                .await
            {
                debug!(err=%e, "Error saving database")
            };
            Ok(())
        } else {
            debug!(%path, "Delete requested for non-existent URL");
            Err(DeletionError::FileNotFound)
        }
    }
}

pub(crate) enum DeletionError {
    Forbidden,
    FileNotFound,
    FilesystemError(Error),
}

impl From<Error> for DeletionError {
    fn from(value: Error) -> Self {
        Self::FilesystemError(value)
    }
}
