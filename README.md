# Flying Sandbox Monster

A proof-of-concept application that sandboxes the Malware Protection engine in an AppContainer on Windows, written in Rust. Flying Sandbox Monster only supports 32-bit builds at this time. Note: there is some _trickery_ performed to make things work since this is a proof-of-concept that interfaces with an undocumented DLL.

![WannaCry Detection Demo](https://github.com/trailofbits/flying-sandbox-monster/raw/master/demo.gif)

## Development Setup
 1. Clone this repo: `git clone https://github.com/trailofbits/flying-sandbox-monster`
 2. Add a new target: `rustup target add i686-pc-windows-msvc` 
 3. Build: `cargo build --target i686-pc-windows-msvc`
 4. Run the unit tests: `cargo test --target i686-pc-windows-msvc`
 
### Manual Dependencies
Flying Sandbox Monster requires dependencies that cannot be automatically included.

 * [Download `mpam-fe.exe`](https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86) (the 32-bit antimalware update file) to the `support\` directory
 * Extract `mpam-fe.exe` in `support\` using `cabextract` or 7Zip.
 * Once complete, check that `support\mpengine.dll` exists, among other files.

### FAQ

#### `cargo build` complains that `msvc targets depend on msvc linker but "link.exe" was not found`

You need to install the [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe) or newer
