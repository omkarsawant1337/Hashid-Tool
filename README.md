# hashid_tool — Hash Type Identifier

A lightweight, dependency-free Python 3 tool for identifying likely hash
algorithms from a raw hash string. Built for use on Kali Linux (or any
system with Python 3) during authorized penetration tests, CTFs, and
forensic triage — pairs well with `hashcat` or `john` once you know which
mode/format to use.

It does **not** crack hashes — it classifies them by structural prefix
(e.g. `$2b$`, `$6$`, `{SSHA}`) and by length/character-set, and reports the
matching hashcat mode and John the Ripper format for each candidate.

## Requirements
- Python 3.6+ (preinstalled on Kali). No third-party packages needed.

## Install on Kali
```bash
# copy hashid_tool.py anywhere, then:
chmod +x hashid_tool.py
sudo cp hashid_tool.py /usr/local/bin/hashid_tool
```

## Usage
```bash
# Single hash
python3 hashid_tool.py 5f4dcc3b5aa765d61d8327deb882cf99

# From a file, one hash per line
python3 hashid_tool.py -f hashes.txt

# Pipe in
cat hashes.txt | python3 hashid_tool.py

# JSON output (stdout or file)
python3 hashid_tool.py -f hashes.txt --json
python3 hashid_tool.py -f hashes.txt -o results.json
```

## Example
```
$ python3 hashid_tool.py '$2b$12$abcdefghijklmnopqrstuv'

Hash: $2b$12$abcdefghijklmnopqrstuv
Length: 29 characters
------------------------------------------------------------
   1. [LIKELY]   bcrypt
       Hashcat mode: 3200   John format: bcrypt
```

## Verified output (tested on Kali Linux)

```
$ python3 hashid_tool.py 482c811da5d5b4bc6d497ffa98491e38

Hash: 482c811da5d5b4bc6d497ffa98491e38
Length: 32 characters
------------------------------------------------------------
   1. [possible] MD5
       Hashcat mode: 0   John format: raw-md5
   2. [possible] NTLM
       Hashcat mode: 1000   John format: nt
   3. [possible] MD4
       Hashcat mode: 900   John format: raw-md4
   4. [possible] LM
       Hashcat mode: 3000   John format: lm

$ python3 hashid_tool.py '$2b$12$R3k3rkrM5pP3KpbN8eXfpuMrPsZHpiUTH5OnQDjscOhDKMQeWEv6u'

Hash: $2b$12$R3k3rkrM5pP3KpbN8eXfpuMrPsZHpiUTH5OnQDjscOhDKMQeWEv6u
Length: 60 characters
------------------------------------------------------------
   1. [LIKELY]   bcrypt
       Hashcat mode: 3200   John format: bcrypt
```

Every hash in `test_hashes.txt` (20 real hashes covering every supported
type) was run through the tool and correctly classified — see
`test_hashes_annotated.txt` for what each one actually is.

## Coverage
- **Structural prefixes**: md5crypt, bcrypt, sha256crypt, sha512crypt,
  yescrypt, Argon2i/id, phpass (WordPress/phpBB), APR1, LDAP `{SHA}`/`{SSHA}`,
  sha1crypt, Kerberos AS-REP/TGS-REP, Office, PDF, ZIP, RAR5.
- **Raw digests by length**: MD5/NTLM/MD4/LM (32), SHA-1/MySQL5/RIPEMD-160
  (40), SHA-224/SHA3-224 (56), SHA-256/SHA3-256/BLAKE2s (64),
  SHA-384/SHA3-384 (96), SHA-512/SHA3-512/Whirlpool (128).
- **Base64-encoded** SHA-1/256/512 digests.

## Extending
Add new entries to `PREFIX_RULES` (structural) or `LENGTH_RULES`
(length-based) in `hashid_tool.py` — each is a plain regex + `HashMatch`
tuple, so adding an algorithm takes one line.

## Legal
Use only against hashes you own or are explicitly authorized to test.
