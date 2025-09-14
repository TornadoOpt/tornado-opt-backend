use tornado_opt_backend::env::EnvVar;

fn main() {
    dotenvy::dotenv().ok();
    let env = envy::from_env::<EnvVar>().expect("Failed to load env var");

    println!("Env var loaded: {:?}", env);
}
