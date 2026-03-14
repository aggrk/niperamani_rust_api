use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

pub async fn send_verification_email(to: &str, token: &str) -> anyhow::Result<()> {
    let app_url   = std::env::var("APP_URL").unwrap_or("http://localhost:3000".into());
    let smtp_host = std::env::var("EMAIL_HOST")?;
    let smtp_user = std::env::var("EMAIL_USER")?;
    let smtp_pass = std::env::var("EMAIL_PASS")?;
    let smtp_port = std::env::var("EMAIL_PORT")?.parse::<u16>()?;
    let from      = std::env::var("EMAIL_FROM")?;

    let verify_url = format!("{}/auth/verify-email?token={}", app_url, token);

    let email = Message::builder()
        .from(from.parse()?)        // ← "Your App <you@domain.com>" format
        .to(to.parse()?)
        .subject("Verify your email address")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"
            <h2>Welcome! Please verify your email.</h2>
            <p>Click the link below to activate your account.
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
            url = verify_url
        ))?;

    let creds = Credentials::new(smtp_user, smtp_pass);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)?
        .port(smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await?;
    Ok(())
}