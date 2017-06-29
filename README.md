# mpclient-rs
A proof-of-concept application that sandboxes the Malware Protection engine within an AppContainer on Windows written in Rust. 

## Status
There is only support for 32-bit builds at this time. Since this is a proof-of-concept that interfaces with an undocumented DLL, there is some trickery performed to make things work.

## Development Setup
 1. Clone this repo: `git clone https://github.com/trailofbits/mpclient-rs`
 2. Add a new target: `rustup target add i686-pc-windows-msvc` 
 3. Build: `cargo build --target i686-pc-windows-msvc`
 4. Run the unit tests: `cargo test --target i686-pc-windows-msvc`
 
### Manual Dependencies
In order to function, **mpclient-rs** requires some additional dependencies that cannot be automatically included. 

 * First, create a directory in the root repository directory called `support/`
 * In `support/`, download `mpam-fe.exe` (the 32-bit antimalware update file) from https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86
 * Extract `mpam-fe.exe` inot `support\` using either `cabextract` or 7Zip.
 * At this point, there should exist a `support\mpengine.dll`
