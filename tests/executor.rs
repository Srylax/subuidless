#[cfg(test)]
mod fchownat;
#[cfg(test)]
mod newfstatat;

#[cfg(feature = "executor")]
subuidless_test::create_docker!(
    "subuidless",
    "subuidless/src",
    "subuidless/Cargo.toml",
    "subuidless/build.rs",
    "subuidless/tests"
);

#[cfg(not(test))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().nth(1).expect("No Argument provided");
    let syscall: Box<dyn subuidless_test::Syscall> = serde_json::from_str(&args)?; // Deserialize to Syscall
    if let Some(str) = syscall.execute()? {
        // Execute Syscall
        std::io::Write::write_all(&mut std::io::stdout(), str.as_ref())?; // Write Response to stdout
    }
    Ok(())
}
