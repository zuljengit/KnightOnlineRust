use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub download: DownloadConfig,
    pub servers: Vec<ServerConfig>,
    pub news: NewsConfig,
    #[serde(default)]
    pub patches: Vec<PatchConfig>,
    pub database: DatabaseConfig,
}

#[derive(Deserialize)]
pub struct GeneralConfig {
    pub listen_port: u16,
    pub last_version: i16,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct DownloadConfig {
    pub ftp_url: String,
    pub ftp_path: String,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub ip: String,
    pub name: String,
    pub user_limit: i16,
}

#[derive(Deserialize)]
pub struct NewsConfig {
    pub title: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct PatchConfig {
    pub filename: String,
    pub version: i16,
}

#[derive(Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
}

pub struct HandlerContext {
    pub last_version: i16,
    pub servers: Vec<ServerState>,
    pub news_title: String,
    pub news_message: String,
    pub ftp_url: String,
    pub ftp_path: String,
    pub patches: Vec<PatchEntry>,
}

pub struct ServerState {
    pub ip: String,
    pub name: String,
    pub user_count: i16,
    pub user_limit: i16,
}

pub struct PatchEntry {
    pub filename: String,
    pub version: i16,
}
