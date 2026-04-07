use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "google-admin")]
#[command(about = "Google Workspace Admin CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// User management commands
    Users {
        #[command(subcommand)]
        command: UserCommands,
    },
    /// Configure CLI settings
    Config {
        /// OAuth2 client ID
        #[arg(long)]
        client_id: Option<String>,
        /// OAuth2 client secret
        #[arg(long)]
        client_secret: Option<String>,
        /// Google Workspace domain
        #[arg(long)]
        domain: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Authenticate with Google Workspace
    Login,
    /// Show authentication status
    Status,
}

#[derive(Subcommand)]
enum UserCommands {
    /// List users in the domain
    List {
        /// Maximum results
        #[arg(short, long, default_value = "100")]
        limit: u32,
        /// Show only specific fields
        #[arg(long)]
        query: Option<String>,
    },
    /// Get user details
    Get {
        /// User email or ID
        user: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    client_id: Option<String>,
    client_secret: Option<String>,
    domain: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
}

impl Config {
    fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("No config directory"))?
            .join("google-admin");
        Ok(dir.join("config.json"))
    }

    fn load() -> Result<Self> {
        let path = Self::path()?;
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&contents)?)
        } else {
            Ok(Self::default())
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now().timestamp() >= exp - 60,
            None => true,
        }
    }
}

const SCOPES: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

// Default OAuth client (same as gmail-cli)
const DEFAULT_CLIENT_ID: &str =
    "690797697044-6kpkd2ethnsren8m5v27qdkj2182eb4n.apps.googleusercontent.com";
const DEFAULT_CLIENT_SECRET: &str = "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";

async fn do_oauth_login(config: &mut Config) -> Result<()> {
    let client_id = config.client_id.as_deref().unwrap_or(DEFAULT_CLIENT_ID);
    let client_secret = config
        .client_secret
        .as_deref()
        .unwrap_or(DEFAULT_CLIENT_SECRET);

    // Start local server on dynamic port to receive callback
    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|e| anyhow!("Failed to start callback server: {}", e))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .unwrap_or(8085);
    let redirect_uri = format!("http://127.0.0.1:{}", port);

    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent",
        AUTH_URL,
        urlencoding::encode(client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(SCOPES)
    );

    println!("Opening browser for authorization...");
    println!("If browser doesn't open, visit: {}", auth_url);

    if let Err(e) = open::that(&auth_url) {
        eprintln!("Failed to open browser: {}", e);
    }

    println!("Waiting for authorization...");

    let request = server
        .recv()
        .map_err(|e| anyhow!("Failed to receive callback: {}", e))?;
    let url = request.url().to_string();

    // Extract code from callback
    let code = url
        .split('?')
        .nth(1)
        .and_then(|q| {
            q.split('&')
                .find(|p| p.starts_with("code="))
                .map(|p| p.trim_start_matches("code=").to_string())
        })
        .ok_or_else(|| anyhow!("No authorization code in callback"))?;

    // Send response to browser
    let response =
        tiny_http::Response::from_string("Authorization successful! You can close this window.");
    let _ = request.respond(response);

    println!("Authorization code received, exchanging for token...");

    // Exchange code for tokens
    let http = reqwest::Client::new();
    let resp = http
        .post(TOKEN_URL)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", &code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", &redirect_uri),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await?;
        bail!("Token exchange failed: {}", body);
    }

    let token_resp: serde_json::Value = resp.json().await?;

    config.access_token = token_resp["access_token"].as_str().map(String::from);
    config.refresh_token = token_resp["refresh_token"].as_str().map(String::from);

    if let Some(expires_in) = token_resp["expires_in"].as_i64() {
        config.expires_at = Some(chrono::Utc::now().timestamp() + expires_in);
    }

    config.save()?;
    println!("Authentication successful!");

    Ok(())
}

async fn refresh_token(config: &mut Config) -> Result<()> {
    let client_id = config.client_id.as_deref().unwrap_or(DEFAULT_CLIENT_ID);
    let client_secret = config
        .client_secret
        .as_deref()
        .unwrap_or(DEFAULT_CLIENT_SECRET);
    let refresh_token = config
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow!("No refresh token. Run: google-admin auth login"))?;

    let http = reqwest::Client::new();
    let resp = http
        .post(TOKEN_URL)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await?;
        bail!("Token refresh failed: {}", body);
    }

    let token_resp: serde_json::Value = resp.json().await?;

    config.access_token = token_resp["access_token"].as_str().map(String::from);
    if let Some(expires_in) = token_resp["expires_in"].as_i64() {
        config.expires_at = Some(chrono::Utc::now().timestamp() + expires_in);
    }

    config.save()?;
    Ok(())
}

struct Client {
    http: reqwest::Client,
    domain: String,
}

impl Client {
    fn new(token: &str, domain: &str) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse()?,
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self {
            http,
            domain: domain.to_string(),
        })
    }

    async fn list_users(&self, max_results: u32, query: Option<&str>) -> Result<serde_json::Value> {
        let mut url = format!(
            "https://admin.googleapis.com/admin/directory/v1/users?domain={}&maxResults={}",
            urlencoding::encode(&self.domain),
            max_results
        );

        if let Some(q) = query {
            url.push_str(&format!("&query={}", urlencoding::encode(q)));
        }

        let resp = self.http.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await?;
            bail!("List users failed ({}): {}", status, body);
        }

        Ok(resp.json().await?)
    }

    async fn get_user(&self, user_key: &str) -> Result<serde_json::Value> {
        let url = format!(
            "https://admin.googleapis.com/admin/directory/v1/users/{}",
            urlencoding::encode(user_key)
        );

        let resp = self.http.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await?;
            bail!("Get user failed ({}): {}", status, body);
        }

        Ok(resp.json().await?)
    }
}

async fn get_client(config: &mut Config) -> Result<Client> {
    if config.is_expired() {
        if config.refresh_token.is_some() {
            eprintln!("Token expired, refreshing...");
            refresh_token(config).await?;
        } else {
            bail!("Token expired. Run: google-admin auth login");
        }
    }

    let token = config
        .access_token
        .as_ref()
        .ok_or_else(|| anyhow!("Not authenticated. Run: google-admin auth login"))?;

    let domain = config.domain.as_ref().ok_or_else(|| {
        anyhow!("No domain configured. Run: google-admin config --domain <domain>")
    })?;

    Client::new(token, domain)
}

fn print_users(value: &serde_json::Value) {
    if let Some(users) = value["users"].as_array() {
        if users.is_empty() {
            println!("No users found");
            return;
        }
        for user in users {
            let email = user["primaryEmail"].as_str().unwrap_or("-");
            let name = user["name"]["fullName"].as_str().unwrap_or("-");
            let suspended = user["suspended"].as_bool().unwrap_or(false);
            let status = if suspended { "suspended" } else { "active" };
            println!("{:<40} {:<10} {}", email, status, name);
        }
    } else {
        println!("No users found");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = Config::load().context("Failed to load config")?;

    match cli.command {
        Commands::Config {
            client_id,
            client_secret,
            domain,
        } => {
            if client_id.is_none() && client_secret.is_none() && domain.is_none() {
                println!("Current configuration:");
                println!(
                    "  client_id: {}",
                    config.client_id.as_deref().unwrap_or("(not set)")
                );
                println!(
                    "  client_secret: {}",
                    config
                        .client_secret
                        .as_ref()
                        .map(|_| "***")
                        .unwrap_or("(not set)")
                );
                println!(
                    "  domain: {}",
                    config.domain.as_deref().unwrap_or("(not set)")
                );
                return Ok(());
            }
            if let Some(id) = client_id {
                config.client_id = Some(id);
            }
            if let Some(secret) = client_secret {
                config.client_secret = Some(secret);
            }
            if let Some(d) = domain {
                config.domain = Some(d);
            }
            config.save()?;
            println!("Configuration saved.");
        }

        Commands::Auth { command } => match command {
            AuthCommands::Login => {
                do_oauth_login(&mut config).await?;
            }
            AuthCommands::Status => {
                if config.access_token.is_some() {
                    println!("Authenticated");
                    if let Some(exp) = config.expires_at {
                        let dt = chrono::DateTime::from_timestamp(exp, 0)
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        println!("  expires: {}", dt);
                        println!("  expired: {}", config.is_expired());
                    }
                } else {
                    println!("Not authenticated");
                }
            }
        },

        Commands::Users { command } => match command {
            UserCommands::List { limit, query } => {
                let client = get_client(&mut config).await?;
                let result = client.list_users(limit, query.as_deref()).await?;
                print_users(&result);
            }
            UserCommands::Get { user } => {
                let client = get_client(&mut config).await?;
                let result = client.get_user(&user).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
    }

    Ok(())
}
