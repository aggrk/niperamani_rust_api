use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

async fn send_email(email: lettre::Message) -> anyhow::Result<()> {
    let smtp_host = std::env::var("EMAIL_HOST")?;
    let smtp_user = std::env::var("EMAIL_USER")?;
    let smtp_pass = std::env::var("EMAIL_PASS")?;

    let creds = Credentials::new(smtp_user, smtp_pass);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)?
        .port(2525)
        .credentials(creds)
        .build();

    mailer.send(email).await?;
    Ok(())
}

pub async fn send_verification_email(to: &str, token: &str) -> anyhow::Result<()> {
    let from    = std::env::var("EMAIL_FROM")?;
    let app_url = std::env::var("APP_URL").unwrap_or("http://localhost:3000".into());
    let url     = format!("{}/auth/verify-email?token={}", app_url, token);

    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject("Verify your email address")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"
            <h2>Welcome! Please verify your email.</h2>
            <p>Click the button below to activate your account.
               This link expires in 24 hours.</p>
            <a href="{url}" style="
                display: inline-block;
                padding: 12px 24px;
                background: #4F46E5;
                color: white;
                text-decoration: none;
                border-radius: 6px;
            ">Verify Email</a>
            <p>Or copy this link: {url}</p>
            "#,
        ))?;

    send_email(email).await
}

pub async fn send_password_reset_email(to: &str, token: &str) -> anyhow::Result<()> {
    let from    = std::env::var("EMAIL_FROM")?;
    let app_url = std::env::var("APP_URL").unwrap_or("http://localhost:3000".into());
    let url     = format!("{}/auth/reset-password?token={}", app_url, token);

    let email = Message::builder()
        .from(from.parse()?)
        .to(to.parse()?)
        .subject("Reset your password")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"
            <h2>Password Reset Request</h2>
            <p>You requested to reset your password.
               Click the button below to set a new password.
               This link expires in 1 hour.</p>
            <a href="{url}" style="
                display: inline-block;
                padding: 12px 24px;
                background: #4F46E5;
                color: white;
                text-decoration: none;
                border-radius: 6px;
            ">Reset Password</a>
            <p>Or copy this link: {url}</p>
            <p>If you did not request a password reset, ignore this email.</p>
            "#,
        ))?;

    send_email(email).await
}