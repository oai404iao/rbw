use crate::prelude::*;

pub async fn register(
    email: &str,
    apikey: crate::locked::ApiKey,
) -> Result<()> {
    let (client, config) = api_client_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

pub async fn login(
    email: &str,
    password: crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, config) = api_client_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            config.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn send_two_factor_email(
    email: &str,
    sso_email_2fa_session_token: &str,
) -> Result<()> {
    let (client, config) = api_client_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let identity = crate::identity::Identity::new(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key =
        match protected_private_key.decrypt_locked_symmetric(&key) {
            Ok(private_key) => crate::locked::PrivateKey::new(private_key),
            Err(e) => return Err(e),
        };

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key =
            match protected_org_key.decrypt_locked_asymmetric(&private_key) {
                Ok(org_key) => crate::locked::Keys::new(org_key),
                Err(e) => return Err(e),
            };
        org_keys.insert(org_id.clone(), org_key);
    }

    Ok((key, org_keys))
}

pub async fn sync() -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    with_exchange_refresh_token_async(|access_token| {
        let access_token = access_token.to_string();
        Box::pin(async move { sync_once(&access_token).await })
    })
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub fn add(
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    with_exchange_refresh_token(|access_token| {
        add_once(access_token, name, data, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(access_token, name, data, notes, folder_id)?;
    Ok(())
}

pub fn edit(
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    with_exchange_refresh_token(|access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
        )
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(id: &str) -> Result<()> {
    with_exchange_refresh_token(|access_token| remove_once(access_token, id))
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove(access_token, id)?;
    Ok(())
}

pub fn list_folders() -> Result<Vec<(String, String)>> {
    with_exchange_refresh_token(|access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client()?;
    client.folders(access_token)
}

pub fn create_folder(name: &str) -> Result<String> {
    with_exchange_refresh_token(|access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

// The database lock covers loading credentials, refreshing, saving, and retrying.
// Persist a rotated refresh token before retrying the business request: the
// server may already have invalidated its predecessor even if that retry fails.
fn with_exchange_refresh_token<F, T>(f: F) -> Result<T>
where
    F: Fn(&str) -> Result<T>,
{
    let (client, config) = api_client()?;
    let email = config.email.as_deref().ok_or(Error::ConfigMissingEmail)?;
    let server = config.server_name();
    let _guard = crate::db::Db::lock(&server, email)?;
    let mut db = crate::db::Db::load(&server, email)?;
    let access_token =
        db.access_token.as_deref().ok_or(Error::NotLoggedIn)?;
    match f(access_token) {
        Err(Error::RequestUnauthorized) => {
            let tokens = client.exchange_refresh_token(
                db.refresh_token.as_deref().ok_or(Error::NotLoggedIn)?,
            )?;
            db.access_token = Some(tokens.access_token);
            if let Some(refresh_token) = tokens.refresh_token {
                db.refresh_token = Some(refresh_token);
            }
            db.save(&server, email)?;
            f(db.access_token.as_deref().ok_or(Error::NotLoggedIn)?)
        }
        result => result,
    }
}

async fn with_exchange_refresh_token_async<F, T>(f: F) -> Result<T>
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send>,
        > + Send
        + Sync,
    T: Send,
{
    let (client, config) = api_client_async().await?;
    let email = config.email.as_deref().ok_or(Error::ConfigMissingEmail)?;
    let server = config.server_name();
    let guard = crate::db::Db::lock_async(&server, email).await?;
    let mut db = crate::db::Db::load_async(&server, email).await?;
    let access_token =
        db.access_token.as_deref().ok_or(Error::NotLoggedIn)?;
    match f(access_token).await {
        Err(Error::RequestUnauthorized) => {
            let tokens = client
                .exchange_refresh_token_async(
                    db.refresh_token.as_deref().ok_or(Error::NotLoggedIn)?,
                )
                .await?;
            db.access_token = Some(tokens.access_token);
            if let Some(refresh_token) = tokens.refresh_token {
                db.refresh_token = Some(refresh_token);
            }
            db.save_async(&server, email, &guard).await?;
            f(db.access_token.as_deref().ok_or(Error::NotLoggedIn)?).await
        }
        result => result,
    }
}

fn api_client() -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load()?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

async fn api_client_async(
) -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load_async().await?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}
