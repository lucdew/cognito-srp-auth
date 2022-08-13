use aws_sdk_cognitoidentityprovider::error::{InitiateAuthError, RespondToAuthChallengeError};
use aws_smithy_client;
use cognito_srp::CognitoSrpError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CognitoSrpAuthError {
    #[error("cognito srp error: {0}")]
    SrpError(#[from] CognitoSrpError),

    #[error("illegal argument: {0}")]
    IllegalArgument(String),

    #[error("io error: {0}")]
    IOError(#[from] io::Error),

    #[error("cognito idp initiate error: {0}")]
    CognitoInitiateError(#[from] aws_smithy_client::SdkError<InitiateAuthError>),

    #[error("cognito idp response to auth challenge error: {0}")]
    CognitoIniateError(#[from] aws_smithy_client::SdkError<RespondToAuthChallengeError>),
}
