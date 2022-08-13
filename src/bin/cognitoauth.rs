use cognitoauth::cognito_srp_auth::{auth, CognitoAuthInput};
use cognitoauth::error::CognitoSrpAuthError;
use structopt::StructOpt;

/// Opt for StructOpt including both region and client_id.
#[derive(StructOpt)]
struct Opt {
    /// The AWS Client ID.
    #[structopt(short, long)]
    client_id: String,

    /// The MFA
    #[structopt(short, long)]
    mfa: String,

    /// The username
    #[structopt(short, long)]
    username: String,

    /// The password
    #[structopt(short, long)]
    password: String,

    /// The pool_id
    #[structopt(short = "o", long = "pool-id")]
    pool_id: String,
}

#[tokio::main]
async fn main() -> Result<(), CognitoSrpAuthError> {
    env_logger::init();
    // Get env variables
    let Opt {
        client_id,
        mfa,
        username,
        password,
        pool_id,
    } = Opt::from_args();

    let input = CognitoAuthInput {
        client_id,
        pool_id,
        username,
        password,
        mfa: Some(mfa),
        client_secret: None,
    };

    let res = auth(input).await?;
    let auth_res = res.unwrap();
    print!("{:?}", auth_res.id_token);

    Ok(())
}
