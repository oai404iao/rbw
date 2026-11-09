use anyhow::Context as _;
use sha2::Digest as _;

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(anyhow::anyhow!(
                "couldn't find host in rbw base url {url_str}"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let email = config_email().await?;
        let (tokens, password) = authenticate(&email, environment).await?;
        let (
            access_token,
            refresh_token,
            kdf,
            iterations,
            memory,
            parallelism,
            protected_key,
        ) = tokens;
        login_success(
            state,
            access_token,
            refresh_token,
            kdf,
            iterations,
            memory,
            parallelism,
            protected_key,
            password,
            db,
            email,
        )
        .await?;
    }

    respond_ack(sock).await?;

    Ok(())
}

type LoginTokens = (
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
);

async fn authenticate(
    email: &str,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<(LoginTokens, rbw::locked::Password)> {
    let url_str = config_base_url().await?;
    let url =
        reqwest::Url::parse(&url_str).context("failed to parse base url")?;
    let Some(host) = url.host_str() else {
        return Err(anyhow::anyhow!(
            "couldn't find host in rbw base url {url_str}"
        ));
    };

    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop
            // if we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let password = rbw::pinentry::getpin(
            &config_pinentry().await?,
            "Master Password",
            &format!("Log in to {host}"),
            err.as_deref(),
            environment,
            true,
        )
        .await
        .context("failed to read password from pinentry")?;
        match rbw::actions::login(email, password.clone(), None, None).await {
            Ok(tokens) => return Ok((tokens, password)),
            Err(rbw::error::Error::TwoFactorRequired {
                providers,
                sso_email_2fa_session_token,
            }) => {
                let supported_types = vec![
                    rbw::api::TwoFactorProviderType::Authenticator,
                    rbw::api::TwoFactorProviderType::Yubikey,
                    rbw::api::TwoFactorProviderType::Email,
                ];

                for provider in supported_types {
                    if providers.contains(&provider) {
                        if provider == rbw::api::TwoFactorProviderType::Email
                        {
                            if let Some(sso_email_2fa_session_token) =
                                sso_email_2fa_session_token
                            {
                                rbw::actions::send_two_factor_email(
                                    email,
                                    &sso_email_2fa_session_token,
                                )
                                .await?;
                            }
                        }
                        let tokens = two_factor(
                            environment,
                            email,
                            password.clone(),
                            provider,
                        )
                        .await?;
                        return Ok((tokens, password));
                    }
                }
                return Err(anyhow::anyhow!(
                    "unsupported two factor methods: {providers:?}"
                ));
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }
    unreachable!()
}

async fn two_factor(
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = rbw::pinentry::getpin(
            &config_pinentry().await?,
            provider.header(),
            provider.message(),
            err.as_deref(),
            environment,
            provider.grab(),
        )
        .await
        .context("failed to read code from pinentry")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match rbw::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    db: rbw::db::Db,
    email: String,
) -> anyhow::Result<()> {
    let db_guard = lock_db().await?;
    let mut db = load_db().await.unwrap_or(db);
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(&db, &db_guard).await?;
    drop(db_guard);

    sync(None, state.clone()).await?;
    let db = load_db().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key = Some(keys);
            state.org_keys = Some(org_keys);
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                &format!(
                    "Unlock the local database for '{}'",
                    rbw::dirs::profile()
                ),
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    Ok(())
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    state.lock().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let sync_update = state.lock().await.sync_update.clone();
    let sync_update_guard = sync_update.lock().await;
    let (protected_key, protected_private_key, protected_org_keys, entries) =
        rbw::actions::sync()
            .await
            .context("failed to sync database from server")?;
    let db_guard = lock_db().await?;
    // Authentication may have advanced in another process since the request.
    // Only replace vault contents, never restore credentials from a snapshot.
    let mut db = load_db().await?;
    state.lock().await.set_master_password_reprompt(&entries);
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db, &db_guard).await?;
    drop(db_guard);
    drop(sync_update_guard);

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

pub async fn sync_interactive(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let reauthentication = state.lock().await.reauthentication.clone();
    let _reauthentication =
        reauthentication.try_lock_owned().map_err(|_| {
            anyhow::anyhow!("reauthentication already in progress")
        })?;

    let config = rbw::config::Config::load_async().await?;
    let email = config.email.as_deref().context("email address not set")?;
    let server = config.server_name();
    // Snapshot before any prompting, including the initial refresh attempt.
    // Never hold the cross-process lock while waiting for user input.
    let guard = rbw::db::Db::lock_async(&server, email).await?;
    let snapshot =
        serde_json::to_value(rbw::db::Db::load_async(&server, email).await?)?;
    drop(guard);

    match sync(None, state.clone()).await {
        Ok(()) => return respond_ack(sock).await,
        Err(error)
            if matches!(
                error.downcast_ref::<rbw::error::Error>(),
                Some(rbw::error::Error::RefreshTokenRejected)
            ) => {}
        Err(error) => return Err(error),
    }

    let prepare_commit = async {
        rbw::pinentry::confirm(
        &config.pinentry,
        "The server rejected the saved login. Reauthenticate and replace the local login and vault only after successful validation?",
        environment,
    )
    .await
    .context("reauthentication was not confirmed")?;

        let (tokens, password) = authenticate(email, environment).await?;
        let (
            access_token,
            refresh_token,
            kdf,
            iterations,
            memory,
            parallelism,
            _,
        ) = tokens;
        let client = rbw::api::Client::new(
            &config.base_url(),
            &config.identity_url(),
            &config.ui_url(),
            config.client_cert_path(),
        );
        let (
            protected_key,
            protected_private_key,
            protected_org_keys,
            entries,
        ) = client
            .sync(&access_token)
            .await
            .context("failed to sync reauthenticated vault")?;
        // The sync profile, rather than the earlier identity response, supplies
        // the protected key that must match the candidate vault.
        let (keys, org_keys) = rbw::actions::unlock(
            email,
            &password,
            kdf,
            iterations,
            memory,
            parallelism,
            &protected_key,
            &protected_private_key,
            &protected_org_keys,
        )
        .map_err(|_| {
            anyhow::anyhow!("failed to unlock reauthenticated vault")
        })?;
        validate_candidate(
            &keys,
            &org_keys,
            &protected_private_key,
            &entries,
        )
        .map_err(|_| {
            anyhow::anyhow!("failed to validate reauthenticated vault")
        })?;

        let candidate = rbw::db::Db {
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            kdf: Some(kdf),
            iterations: Some(iterations),
            memory,
            parallelism,
            protected_key: Some(protected_key),
            protected_private_key: Some(protected_private_key),
            protected_org_keys,
            entries,
        };
        let sync_update = state.lock().await.sync_update.clone();
        let sync_update_guard = sync_update.lock_owned().await;
        let guard = rbw::db::Db::lock_async(&server, email).await?;
        let current = rbw::db::Db::load_async(&server, email).await?;
        if serde_json::to_value(current)? != snapshot {
            anyhow::bail!("local database changed during reauthentication; retry sync --reauth");
        }
        let locked_state = state.clone().lock_owned().await;
        Ok::<_, anyhow::Error>((
            candidate,
            keys,
            org_keys,
            sync_update_guard,
            guard,
            locked_state,
        ))
    };
    let (
        candidate,
        keys,
        org_keys,
        sync_update_guard,
        guard,
        mut locked_state,
    ) = tokio::select! {
        biased;
        _ = sock.disconnected() => anyhow::bail!("reauthentication cancelled: client disconnected"),
        result = prepare_commit => result?,
    };
    // Once replacement starts, finish installing matching in-memory keys even
    // if the client disconnects or persistence reports uncertain durability.
    let durability_error = match candidate
        .save_async(&server, email, &guard)
        .await
    {
        Ok(()) => None,
        Err(error @ rbw::error::Error::SaveDbCommitted { .. }) => Some(error),
        Err(error) => return Err(error.into()),
    };
    locked_state.priv_key = Some(keys);
    locked_state.org_keys = Some(org_keys);
    locked_state.set_master_password_reprompt(&candidate.entries);
    locked_state.set_timeout();
    drop(locked_state);
    drop(guard);
    drop(sync_update_guard);

    if let Some(error) = durability_error {
        return Err(error).context(
            "reauthentication committed, but cache durability is uncertain",
        );
    }

    if let Err(error) = subscribe_to_notifications(state).await {
        eprintln!("failed to subscribe to notifications: {error}");
    }
    respond_ack(sock).await
}

fn validate_candidate(
    account_keys: &rbw::locked::Keys,
    org_keys: &std::collections::HashMap<String, rbw::locked::Keys>,
    protected_private_key: &str,
    entries: &[rbw::db::Entry],
) -> anyhow::Result<()> {
    use pkcs8::DecodePrivateKey as _;
    use zeroize::Zeroize as _;

    let mut private_key =
        rbw::cipherstring::CipherString::new(protected_private_key)?
            .decrypt_symmetric(account_keys, None)?;
    let parsed = rsa::RsaPrivateKey::from_pkcs8_der(&private_key);
    private_key.zeroize();
    parsed.context("invalid private key")?;

    for entry in entries {
        let keys = match entry.org_id.as_deref() {
            Some(id) => {
                org_keys.get(id).context("missing organization key")?
            }
            None => account_keys,
        };
        let entry_key = entry
            .key
            .as_deref()
            .map(|encrypted| {
                let key = rbw::cipherstring::CipherString::new(encrypted)?
                    .decrypt_locked_symmetric(keys)?;
                anyhow::ensure!(
                    key.data().len() >= 64,
                    "invalid item key length"
                );
                Ok::<_, anyhow::Error>(rbw::locked::Keys::new(key))
            })
            .transpose()?;
        let decrypt = |encrypted: Option<&str>| -> anyhow::Result<()> {
            if let Some(encrypted) =
                encrypted.filter(|value| !value.is_empty())
            {
                let mut plaintext =
                    rbw::cipherstring::CipherString::new(encrypted)?
                        .decrypt_symmetric(keys, entry_key.as_ref())?;
                let valid_utf8 = std::str::from_utf8(&plaintext).is_ok();
                plaintext.zeroize();
                anyhow::ensure!(valid_utf8, "invalid decrypted text");
            }
            Ok(())
        };
        decrypt(Some(&entry.name))?;
        // Folders use the account key, not organization or individual keys.
        if let Some(folder) =
            entry.folder.as_deref().filter(|value| !value.is_empty())
        {
            let mut plaintext = rbw::cipherstring::CipherString::new(folder)?
                .decrypt_symmetric(account_keys, None)?;
            let valid_utf8 = std::str::from_utf8(&plaintext).is_ok();
            plaintext.zeroize();
            anyhow::ensure!(valid_utf8, "invalid decrypted folder text");
        }
        decrypt(entry.notes.as_deref())?;
        for field in &entry.fields {
            decrypt(field.name.as_deref())?;
            decrypt(field.value.as_deref())?;
        }
        for history in &entry.history {
            decrypt(Some(&history.password))?;
        }
        match &entry.data {
            rbw::db::EntryData::Login {
                username,
                password,
                totp,
                uris,
            } => {
                for value in [username, password, totp] {
                    decrypt(value.as_deref())?;
                }
                for uri in uris {
                    decrypt(Some(&uri.uri))?;
                }
            }
            rbw::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                for value in [
                    cardholder_name,
                    number,
                    brand,
                    exp_month,
                    exp_year,
                    code,
                ] {
                    decrypt(value.as_deref())?;
                }
            }
            rbw::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                for value in [
                    title,
                    first_name,
                    middle_name,
                    last_name,
                    address1,
                    address2,
                    address3,
                    city,
                    state,
                    postal_code,
                    country,
                    phone,
                    email,
                    ssn,
                    license_number,
                    passport_number,
                    username,
                ] {
                    decrypt(value.as_deref())?;
                }
            }
            rbw::db::EntryData::SecureNote => {}
            rbw::db::EntryData::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => {
                for value in [private_key, public_key, fingerprint] {
                    decrypt(value.as_deref())?;
                }
            }
        }
    }
    Ok(())
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state
        .master_password_reprompt
        .contains(&master_password_reprompt)
    {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(anyhow::anyhow!("failed to find kdf type in db"));
        };

        let Some(iterations) = db.iterations else {
            return Err(anyhow::anyhow!(
                "failed to find number of iterations in db"
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected key in db"
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "Master Password",
                "Accessing this entry requires the master password",
                err.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read password from pinentry")?;
            match rbw::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok(_) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let plaintext =
        decrypt_cipher(state, environment, cipherstring, entry_key, org_id)
            .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.lock().await;
    let Some(keys) = state.key(org_id) else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
) -> anyhow::Result<()> {
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            anyhow::anyhow!("couldn't store value to clipboard: {e}")
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    config.email.map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        Ok,
    )
}

async fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        rbw::db::Db::load_async(&config.server_name(), email)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn lock_db() -> anyhow::Result<std::fs::File> {
    let config = rbw::config::Config::load_async().await?;
    let email = config.email.as_deref().context("email address not set")?;
    Ok(rbw::db::Db::lock_async(&config.server_name(), email).await?)
}

async fn save_db(
    db: &rbw::db::Db,
    guard: &std::fs::File,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email, guard)
            .await
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

async fn config_base_url() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_pinentry() -> anyhow::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(anyhow::Error::new)?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Matching entry has no private key")
                    })?;

                let private_key_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    private_key_enc,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await?;

                return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(
                    private_key_plaintext,
                )
                .map_err(anyhow::Error::new);
            }
        }
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
