use crate::filesystem::{
    DeletionError, LocalTokenizedFilesystem, SaveError, UserToken, XXH3_128Hash,
};
use crate::settings::Settings;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, Response, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::{
    extract::{DefaultBodyLimit, Multipart}, response::Redirect,
    routing::{get, post},
    Json,
    Router,
};
use axum_extra::extract::TypedHeader;
use axum_extra::headers;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use headers::UserAgent;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp, Zoned};
use mime::Mime;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio_util::io::ReaderStream;
use tower_http::{
    compression::CompressionLayer,
    limit::RequestBodyLimitLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{debug, error, info, instrument, trace, Level};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter};

mod filesystem;
mod settings;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            format!(
                "{}=debug,tower_http=debug,axum::rejection=trace",
                env!("CARGO_CRATE_NAME")
            )
            .into()
        }))
        .init();

    trace!("Initializing settings");
    let settings = Settings::new().unwrap();
    info!(settings = ?settings, "Loaded server settings");
    info!(?settings.bind_http, bind_https = %settings.bind_https, upload_limit = settings.upload_size_limit, "Starting Cabinet");
    debug!("Creating HTTP and HTTPS servers");

    let http_server = http_server(&settings);
    let https_server = https_server(&settings);

    let _ = tokio::join!(http_server, https_server);
}

async fn http_server(settings: &Settings) {
    trace!(?settings.bind_http, "Entering http_server");
    if settings.bind_http.is_none() {
        debug!("HTTP bind address not configured; skipping HTTP redirect server");
        return;
    }

    let fqdn = settings.fqdn_https();

    let app = Router::new().route(
        "/",
        get(async move |uri: axum::http::Uri| {
            let target = format!(
                "https://{}{}",
                fqdn,
                uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
            );
            Redirect::permanent(&target)
        }),
    );

    debug!(addr = %settings.bind_http.unwrap(), "Starting HTTP service");
    axum_server::bind(settings.bind_http.unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

pub(crate) struct AppState {
    pub(crate) fs: LocalTokenizedFilesystem,
    pub(crate) settings: Settings,
}

async fn https_server(settings: &Settings) {
    trace!("Entering https_server");
    let state = Arc::new(AppState {
        fs: LocalTokenizedFilesystem::new(&settings.storage_path)
            .await
            .unwrap(),
        settings: settings.clone(),
    });
    debug!("Initialized AppState");

    let app = Router::new()
        .route(
            "/",
            get(|| async {
                Html::from(
                    r#"
        <!doctype html>
        <html>
            <head></head>
            <body>
                <form action="/" method="post" enctype="multipart/form-data">
                    <label>
                        Upload file:
                        <input type="file" name="file" multiple>
                    </label>

                    <input type="submit" value="Upload files">
                </form>
            </body>
        </html>
        "#,
                )
            })
            .post(post_public),
        )
        .route("/upload", post(post_public))
        .route(
            "/{*file_path}",
            get(get_public).post(modify_public).delete(delete_public),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(settings.upload_size_limit))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .include_headers(true)
                        .level(Level::DEBUG),
                )
                .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .level(Level::DEBUG),
                )
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        )
        .layer(
            CompressionLayer::new()
                .br(true)
                .gzip(true)
                .zstd(true)
                .deflate(true),
        )
        .with_state(state);

    debug!(addr = %settings.bind_https, "Starting HTTPS service");
    axum_server::bind_rustls(
        settings.bind_https,
        settings.tls_config.to_rustlsconfig(&settings.fqdn).await,
    )
    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .unwrap();
}

struct CubicDecay {
    min_age: Span,
    max_age: Span,
    power: i32,
}

impl CubicDecay {
    const fn new(min_age: Span, max_age: Span, power: i32) -> Self {
        Self {
            min_age,
            max_age,
            power,
        }
    }
    fn calculate_lifespan(
        &self,
        starting_date: &Zoned,
        file_size: usize,
        max_size: usize,
    ) -> Result<Zoned, jiff::Error> {
        let minimum_expiration = starting_date.checked_add(self.min_age)?;
        minimum_expiration.checked_add(
            (self.min_age.to_duration(starting_date)? - self.max_age.to_duration(starting_date)?)
                .mul_f64((file_size as f64 / max_size as f64 - 1f64).powi(self.power)),
        )
    }
}

enum ExpireStrategy {
    Never,
    Exact(Zoned),
    Offset(Span),
    Cubic(Box<CubicDecay>),
}
impl ExpireStrategy {
    fn calculate_lifespan(
        &self,
        starting_date: &Zoned,
        file_size: usize,
        max_size: usize,
    ) -> Result<Zoned, jiff::Error> {
        match self {
            ExpireStrategy::Never => Ok(Zoned::new(Timestamp::MAX, TimeZone::UTC)),
            ExpireStrategy::Cubic(cubic) => {
                cubic.calculate_lifespan(starting_date, file_size, max_size)
            }
            ExpireStrategy::Exact(expiry_date) => Ok(expiry_date.clone()),
            ExpireStrategy::Offset(span) => Ok(starting_date.checked_add(span)?),
        }
    }
}

struct PostDataBuilder {
    secret: Option<bool>,
    file_name: Option<String>,
    file_size: Option<usize>,
    file_data: Option<Vec<u8>>,
    content_encoding: Option<Mime>,
    nsfw: Option<bool>,
    expire_strategy: Option<ExpireStrategy>,
    uploader_ip: SocketAddr,
    uploader_ua: String,
}

#[derive(Debug, Clone)]
enum BuilderError {
    MissingFileName,
    MissingFileData,
    OverflowingExpirationSpan(jiff::Error),
    MIMEError,
}

impl From<jiff::Error> for BuilderError {
    fn from(e: jiff::Error) -> Self {
        Self::OverflowingExpirationSpan(e)
    }
}

impl PostDataBuilder {
    fn new(uploader_ip: SocketAddr, uploader_ua: String) -> Self {
        info!(ip = %uploader_ip, ua = %uploader_ua, "Creating PostDataBuilder");
        Self {
            secret: None,
            file_name: None,
            file_size: None,
            file_data: None,
            content_encoding: None,
            nsfw: None,
            expire_strategy: None,
            uploader_ip,
            uploader_ua,
        }
    }
    fn with_secret(&mut self, secret: bool) -> &mut Self {
        debug!(secret = secret, "Setting secret flag");
        self.secret = Some(secret);
        self
    }
    fn with_file_name(&mut self, file_name: String) -> &mut Self {
        debug!(name = %file_name, "Setting file name");
        self.file_name = Some(file_name);
        self
    }
    fn with_file_data(&mut self, file_data: Vec<u8>) -> &mut Self {
        debug!(size = file_data.len(), "Setting file data");
        self.file_data = Some(file_data);
        self
    }
    fn with_file_size(&mut self, file_size: usize) -> &mut Self {
        debug!(size = file_size, "Setting file size");
        self.file_size = Some(file_size);
        self
    }
    fn with_content_type(&mut self, content_type: &str) -> &mut Self {
        self.content_encoding = Mime::from_str(content_type).ok();
        self
    }
    fn with_nsfw(&mut self, nsfw: bool) -> &mut Self {
        debug!(nsfw = nsfw, "Setting NSFW flag");
        self.nsfw = Some(nsfw);
        self
    }
    fn with_expire_strategy(&mut self, strategy: ExpireStrategy) -> &mut Self {
        debug!("Setting expire strategy");
        self.expire_strategy = Some(strategy);
        self
    }
    fn construct(self, settings: &Settings) -> Result<PostData, BuilderError> {
        info!("Constructing PostData from builder");
        let secret = self.secret.unwrap_or(false);
        let file_name = LocalTokenizedFilesystem::sanitize_file_name(
            &self.file_name.ok_or(BuilderError::MissingFileName)?,
        );
        let file_data = self.file_data.ok_or(BuilderError::MissingFileData)?;
        let file_size = self.file_size.unwrap_or(file_data.len());

        let creation_date = Timestamp::now().to_zoned(TimeZone::UTC);

        static SERVER_EXPIRE_STRATEGY: OnceLock<CubicDecay> = OnceLock::new();
        let server_expire_strategy = SERVER_EXPIRE_STRATEGY
            .get_or_init(|| CubicDecay::new(settings.min_file_age, settings.max_file_age, 3));
        let mut expiration_date = server_expire_strategy.calculate_lifespan(
            &creation_date,
            file_size,
            settings.upload_size_limit,
        )?;

        if let Some(user_strategy) = self.expire_strategy {
            let user_edate = user_strategy.calculate_lifespan(
                &creation_date,
                file_size,
                settings.upload_size_limit,
            )?;
            if user_edate < creation_date {
                expiration_date = user_edate;
            }
        }

        info!("Hashing file data (XXH3-128)");
        let file_hash = XXH3_128Hash::calculate(&file_data);

        info!("Determining file MIME");
        let file_mime: Mime = tree_magic_mini::from_u8(&file_data)
            .parse()
            .or(Err(BuilderError::MIMEError))?;

        info!(name = %file_name, size = file_size, mime = %file_mime, secret = secret, "Constructing PostData");
        Ok(PostData {
            secret,
            file_name,
            expiration_date,
            file_size,
            file_mime,
            file_hash,
            file_data,
            nsfw: self.nsfw.unwrap_or(false), // Too lazy to implement rn
            creation_date,
            uploader_ip: self.uploader_ip,
            uploader_ua: self.uploader_ua,
            access_token: UserToken::generate(),
        })
    }
}

fn parse_expire_strategy(num: String) -> Result<ExpireStrategy, (StatusCode, Box<str>)> {
    let num = num.parse::<i64>().or(Err((
        StatusCode::BAD_REQUEST,
        "Can't parse `expires` field as a u64".into(),
    )))?;
    if num < 0 {
        Err((StatusCode::BAD_REQUEST, "Invalid `expires` value.".into()))
    } else if num < 175307616 {
        Ok(ExpireStrategy::Offset(Span::new().hours(num)))
    } else {
        Ok(ExpireStrategy::Exact(
            Timestamp::from_second(num)
                .unwrap_or(Timestamp::MAX)
                .to_zoned(TimeZone::UTC),
        ))
    }
}

struct PostData {
    secret: bool,
    file_name: String,
    file_size: usize,
    file_mime: Mime,
    file_data: Vec<u8>,
    file_hash: XXH3_128Hash,
    nsfw: bool,
    creation_date: Zoned,
    expiration_date: Zoned,
    uploader_ip: SocketAddr,
    uploader_ua: String,
    access_token: UserToken,
}

impl PostData {
    fn builder(uploader_ip: SocketAddr, uploader_ua: String) -> PostDataBuilder {
        PostDataBuilder::new(uploader_ip, uploader_ua)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PostResponseJSON {
    location: String,
    access_token: String,
    expires: String,
}

#[instrument(
    skip(user_agent, app_state, multipart),
    fields(ip = %addr, ua = %user_agent.to_string())
)]
async fn post_public(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: TypedHeader<UserAgent>,
    State(app_state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response<Body>, (StatusCode, Box<str>)> {
    info!("Entered post_public handler");
    is_blocked(&app_state, &user_agent, &addr).await?;
    let mut post = PostData::builder(addr, user_agent.to_string());
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (e.status(), e.body_text().into()))?
    {
        let name = field
            .name()
            .ok_or((StatusCode::BAD_REQUEST, "A field w/o a name. wtf.".into()))?
            .to_string();
        debug!(field = %name, "Processing multipart field");
        if name == "file" {
            post.with_file_name(
                field
                    .file_name()
                    .ok_or((
                        StatusCode::BAD_REQUEST,
                        "A file w/o a file name. wtf.".into(),
                    ))?
                    .to_string(),
            );
            if let Some(enc) = field.content_type() {
                post.with_content_type(enc);
            }
            let data = field.bytes().await.or(Err((
                StatusCode::BAD_REQUEST,
                "Error extracting data.".into(),
            )))?;
            debug!(bytes = data.len(), "Got file bytes from multipart");
            post.with_file_size(data.len());
            post.with_file_data(data.into());
        } else if name == "secret" {
            post.with_secret(true);
        } else if name == "nsfw" {
            post.with_nsfw(true);
        } else if name == "expire" {
            let num = field
                .text()
                .await
                .map_err(|e| (e.status(), e.body_text().into()))?;
            debug!(expires = %num, "Parsed expire field");
            post.with_expire_strategy(parse_expire_strategy(num)?);
        }
    }
    let postdata = post
        .construct(&app_state.settings)
        .map_err(|err| {
            error!(err = ?err, "Failure constructing PostData err");
            err
        })
        .map_err(|val| match val {
            BuilderError::MissingFileData | BuilderError::MissingFileName => (
                StatusCode::BAD_REQUEST,
                "Missing file data or file name.".into(),
            ),
            BuilderError::OverflowingExpirationSpan(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error calculating expiration date.".into(),
            ),
            BuilderError::MIMEError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't determine file type.".into(),
            ),
        })?;
    info!("PostData constructed; saving file");
    let token = postdata.access_token.clone();
    let expires = postdata.expiration_date.clone();
    let uri = app_state.fs.save(postdata).await.map_err(|err| match err {
        SaveError::FileRestricted => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "File hash restricted.".into(),
        ),
        SaveError::FileSystemError(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error saving file.".into(),
        ),
    })?;
    info!(uri = %uri, token = %token, ip = %addr, ua = %user_agent.to_string(), "File uploaded");
    let response = PostResponseJSON {
        location: format!("/{uri}"),
        expires: expires.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        access_token: token.to_string(),
    };

    Ok(
        match Response::builder()
            .status(201)
            .header(header::LOCATION, response.location.clone())
            .header(header::EXPIRES, response.expires.clone())
            .header("X-Token", response.access_token.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Json(response).into_response().into_body())
        {
            Ok(b) => b,
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error creating response.".into(),
                ));
            }
        },
    )
}

#[instrument(skip(user_agent, app_state), fields(ip = %addr, ua = %user_agent.to_string(), path = %file_path
))]
async fn get_public(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: TypedHeader<UserAgent>,
    Path(file_path): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> Result<Response<Body>, (StatusCode, Box<str>)> {
    info!("Entered get_public handler");
    is_blocked(&app_state, &user_agent, &addr).await?;
    let file_tup = app_state.fs.get(file_path.as_str()).await;
    if let Err(err) = file_tup {
        return match err.kind() {
            ErrorKind::ConnectionRefused => {
                info!(path = %file_path, ip = %addr, ua = %user_agent.to_string(), "File is restricted");
                Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "File has been restricted.".into(),
                ))
            }
            ErrorKind::NotFound => {
                info!(path = %file_path, ip = %addr, ua = %user_agent.to_string(), "File not found");
                Err((StatusCode::NOT_FOUND, "File not found.".into()))
            }
            _ => {
                info!(path = %file_path, err=%err, "Error opening file!");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error opening file.".into(),
                ))
            }
        };
    }
    let file_tup = file_tup.unwrap();
    info!(path = %file_path, ip = %addr, ua = %user_agent.to_string(), "Serving file");
    Ok(
        match Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, file_tup.1.mime_type.to_string())
            .header(
                header::EXPIRES,
                file_tup
                    .1
                    .expiration_date
                    .strftime("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string(),
            )
            .body(Body::from_stream(ReaderStream::new(file_tup.0)))
        {
            Ok(b) => b,
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error.".into(),
                ));
            }
        },
    )
}

#[instrument(skip(app_state, user_agent, addr))]
async fn is_blocked(
    app_state: &AppState,
    user_agent: &UserAgent,
    addr: &SocketAddr,
) -> Result<(), (StatusCode, Box<str>)> {
    info!("Checking blocklists");
    if app_state.fs.database.is_ip_blocked(addr).await
        | app_state.fs.database.is_ua_blocked(user_agent).await
    {
        Err((
            StatusCode::FORBIDDEN,
            "You have been blocked. Fuck off.".into(),
        ))
    } else {
        Ok(())
    }
}

#[instrument(skip(app_state, token))]
async fn delete_file(
    app_state: Arc<AppState>,
    file_path: &str,
    token: &UserToken,
) -> Result<Response<Body>, (StatusCode, Box<str>)> {
    info!(path = %file_path, "Delete request received");
    match app_state.fs.remove_file(file_path, token).await {
        Ok(_) => match Response::builder().status(200).body(Body::empty()) {
            Ok(b) => Ok(b),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating response.".into(),
            )),
        },
        Err(DeletionError::Forbidden) => {
            match Response::builder().status(403).body(Body::empty()) {
                Ok(b) => Ok(b),
                Err(_) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error creating response.".into(),
                )),
            }
        }
        Err(DeletionError::FileNotFound) => {
            match Response::builder().status(404).body(Body::empty()) {
                Ok(b) => Ok(b),
                Err(_) => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error creating response.".into(),
                )),
            }
        }
        Err(DeletionError::FilesystemError(e)) => match Response::builder()
            .status(500)
            .body(Body::from(format!("Error deleting file: {}", e)))
        {
            Ok(b) => Ok(b),
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error creating response.".into(),
            )),
        },
    }
}

#[instrument(skip(user_agent, auth_token, app_state), fields(ip = %addr, ua = %user_agent.to_string(), path = %file_path
))]
async fn delete_public(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: TypedHeader<UserAgent>,
    auth_token: TypedHeader<Authorization<Bearer>>,
    Path(file_path): Path<String>,
    State(app_state): State<Arc<AppState>>,
) -> Result<Response<Body>, (StatusCode, Box<str>)> {
    info!("Entered delete_public handler");
    is_blocked(&app_state, &user_agent, &addr).await?;
    let token: UserToken = auth_token.try_into()?;
    delete_file(app_state, file_path.as_str(), &token).await
}

#[instrument(skip(user_agent, auth_token, app_state, multipart), fields(ip = %addr, ua = %user_agent.to_string(), path = %file_path
))]
async fn modify_public(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: TypedHeader<UserAgent>,
    auth_token: TypedHeader<Authorization<Bearer>>,
    Path(file_path): Path<String>,
    State(app_state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response<Body>, (StatusCode, Box<str>)> {
    info!("Entered modify_public handler");
    is_blocked(&app_state, &user_agent, &addr).await?;
    let token: UserToken = auth_token.try_into()?;
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field
            .name()
            .ok_or((StatusCode::BAD_REQUEST, "A field w/o a name. wtf.".into()))?
            .to_string();
        debug!(field = %name, "Processing multipart field in modify_public");
        if name == "delete" {
            let res = delete_file(app_state.clone(), file_path.as_str(), &token).await;
            match &res {
                Ok(_) => {
                    info!(path = %file_path, ip = %addr, ua = %user_agent.to_string(), "File deleted")
                }
                Err((code, _)) => {
                    error!(path = %file_path, status = %code, ip = %addr, ua = %user_agent.to_string(), "Delete failed")
                }
            }
            return res;
        }
    }
    match Response::builder()
        .status(200)
        .body(Body::from("Nothing happened."))
    {
        Ok(b) => Ok(b),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error creating response.".into(),
        )),
    }
}
