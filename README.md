# mpclient-rs
Sandboxing the Windows Malware Protection service with AppContainers...in Rust.

## Status
Currently, this does not work within an AppContainer. We are currently investigating the cause.

## Manual Dependencies
In order to function, **mpclient-rs** requires some additional dependencies that cannot be automatically included. 

 * First, create a directory in the root repository directory called `support/`
 * In `support/`, download `mpam-fe.exe` (the 32-bit antimalware update file) from https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86
 * Extract `mpam-fe.exe` using either `cabextract` or 7Zip.
