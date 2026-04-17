# Major parts is done!
♥️ I will be continuing on this! I actually finished the file-hider-rootkit (for fedora, freshly updated 2026) at a hospital stay. (April 17th from the time writing this!) I am soon home though!
Sending hugs to everyone reading this! \(^v^)/

<img width="3300" height="2830" alt="Made With NotebookLM" src="https://github.com/user-attachments/assets/21174472-36a4-49d6-ad61-26968948ab5f" /> \
*Made With NotebookLM*

----

**A suite of linux-rootkits** \
Rootkits for Kernel  6.12.74

**Goal of this** \
As I turned 26, I thought "lets make another rootkit for a new kernel, since fedora/qubes updated", and yeah here I am!
create original ideas like for example a DISK-HIDER or SECRET-STORAGE.


PROGRESS \
**DEBIAN**
- [X] FILE HIDER (including directories - 'everything is a file') - done at apr 15th I think
- [x] LKM KEYLOGGER - Done at apr 17th
- [ ] LKM COMMAND EXECUTION
- [ ] NETWORK CONNECTIONS
- [ ] RANDOMNESS BACKDOOR
- [ ] ELEVATION OF PRIVILEGE 
- [ ] PERSISTENCE

**FEDORA**
- [X] **FILE HIDER (including directories - 'everything is a file')** - Done at Apr 17th. Was a good challenge.
- [X] LKM KEYLOGGER - Done at apr 17th
- [X] ELEVATION OF PRIVILEGE - Done at apr 15th~
- [X] LKM COMMAND EXECUTION - Done at apr 16th~
- [ ] NETWORK CONNECTIONS
- [ ] RANDOMNESS BACKDOOR
- [ ] PERSISTENCE

**TODO**
- [ ] make a script which disabled security measures like KASLR and stuff, for the user, so the user doesn't have to copy paste commands.
  - [ ] lockdown
  - [ ] setenforce=0
  - [ ] kaslr


**Disclaimer** \
As usual, only use this on your own macine, Thank you very much!
And, this rootkit might (with 70~80% probability) crash your specific VM/bare metal because i've used dirty coding here, as the kernel updated, and also I was feverish so, this is probably bad..
..But it works. Thats what I consider a success.
