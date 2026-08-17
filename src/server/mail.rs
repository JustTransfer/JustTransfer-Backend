use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use crate::consts::SERVER_MODE;
use crate::error::ServerError;

pub fn init_mailer(smtp_server: &str, smtp_username: &str, smtp_password: &str) -> SmtpTransport {

    if SERVER_MODE.get().unwrap() == "development" {
        tracing::info!("Server mode is 'development', emails will be printed to console instead of being sent");
        tracing::warn!("The connection will still be established to the SMTP server");
    }

    let creds = Credentials::new(smtp_username.to_owned(), smtp_password.to_owned());

    // Open a remote connection to the SMTP server
    SmtpTransport::relay(smtp_server)
        .unwrap()
        .credentials(creds)
        .build()
}

fn send_mail(receiver: &str, subject: &str, body: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    if SERVER_MODE.get().unwrap() == "development" {
        tracing::info!("--- Email to {} ---\nSubject: {}\n\n{}\n--- End of email ---", receiver, subject, body);
        return Ok(());
    }

    let email = Message::builder()
        .from(Mailbox::new(Some("JustTransfer".to_owned()), crate::consts::SMTP_MAIL.get().unwrap().to_owned().parse().unwrap()))
        .to(Mailbox::new(Some(receiver.to_owned()), receiver.parse().unwrap()))
        .subject(subject.to_owned())
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .unwrap();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            tracing::info!("Email sent to {}", receiver);
            Ok(())
        }
        Err(e) => {
            // Log the error but returns success
            tracing::error!("Could not send email to {}: {:?}", receiver, e);
            Ok(())
        }
    }
}

pub fn send_verification_email(receiver: &str, link: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "Welcome to JustTransfer! Please verify your email address";
    let body = format!("Hello {},\n\nThank you for registering with JustTransfer! To complete your registration, please click the following link to verify your email address:\n\n{}\n\nIf you did not create an account with JustTransfer, please ignore this email.\n\nBest regards,\nJustTransfer Team", receiver, link);

    send_mail(receiver, subject, &body, mailer)
}

pub fn send_notification_account_creation_email_taken(receiver: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "JustTransfer account creation attempt";
    let body = format!("Hello {},\n\nWe received an attempt to create a JustTransfer account using your email address. You already have an account, so nothing was created or changed. If you initiated this request, you can simply log in instead. If you did not, please ignore this email, or reset your password if you're concerned:\n\n{}/reset-password\n\nBest regards,\nJustTransfer Team", receiver, crate::consts::FRONTEND_URL.get().unwrap());

    send_mail(receiver, subject, &body, mailer)
}

pub fn send_password_reset_email(receiver: &str, link: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "JustTransfer password reset request";
    let body = format!("Hello {},\n\nWe received a request to reset your JustTransfer password. If you initiated this request, please click the following link to reset your password:\n\n{}\n\nIf you did not request a password reset, please ignore this email. Your password will remain unchanged.\n\nBest regards,\nJustTransfer Team", receiver, link);

    send_mail(receiver, subject, &body, mailer)
}

pub fn send_password_reset_confirmation_email(receiver: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "Your JustTransfer password has been reset";
    let body = format!("Hello {},\n\nThis is a confirmation that your JustTransfer password has been reset. If you did not initiate this request, please go to the JustTransfer website and reset your password immediately.\n\nBest regards,\nJustTransfer Team", receiver);

    send_mail(receiver, subject, &body, mailer)
}

pub fn send_password_changed_notification_email(receiver: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "Your JustTransfer password has been changed";
    let body = format!("Hello {},\n\nThis is a notification that your JustTransfer password has been changed. If you did not initiate this change, please go to the JustTransfer website and reset your password immediately.\n\nBest regards,\nJustTransfer Team", receiver);

    send_mail(receiver, subject, &body, mailer)
}

pub fn send_transfer_notification_email(receiver: &str, url: &str, mailer: &SmtpTransport) -> Result<(), ServerError> {

    let subject = "You have received a new file transfer on JustTransfer";
    let body = format!("Hello {},\n\nYou have received a new file transfer on JustTransfer. Use the following link to access the transfer:\n\n{}\n\nBest regards,\nJustTransfer Team", receiver, url);

    send_mail(receiver, subject, &body, mailer)
}