# flying-sandbox-monster
A proof-of-concept application that sandboxes the Malware Protection engine within an AppContainer on Windows written in Rust. 

![WannaCry Detection Demo](https://github.com/trailofbits/flying-sandbox-monster/raw/master/demo.gif)

## Status
There is only support for 32-bit builds at this time. Since this is a proof-of-concept that interfaces with an undocumented DLL, there is some trickery performed to make things work.

## Development Setup
 1. Clone this repo: `git clone https://github.com/trailofbits/flying-sandbox-monster`
 2. Add a new target: `rustup target add i686-pc-windows-msvc` 
 3. Build: `cargo build --target i686-pc-windows-msvc`
 4. Run the unit tests: `cargo test --target i686-pc-windows-msvc`
 
### Manual Dependencies
In order to function, **flying-sandbox-monster** requires some additional dependencies that cannot be automatically included. 

 * First, create a directory in the root repository directory called `support/`
 * In `support/`, download `mpam-fe.exe` (the 32-bit antimalware update file) from https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86
 * Extract `mpam-fe.exe` into `support\` using `cabextract` or 7Zip.
 * At this point, `support\mpengine.dll` should exist, among other files.

### FAQ

#### `cargo build` complains that `msvc targets depend on msvc linker but "link.exe" was not found`

You need to at least install [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe)
