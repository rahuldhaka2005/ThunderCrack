# ThunderCrack
A powerful password cracking tool
ThunderCrack
ThunderCrack is a powerful, multi-threaded password cracking tool inspired by John the Ripper, designed for educational purposes and authorized penetration testing. It supports dictionary attacks, brute force attacks, and rule-based mangling, with support for multiple hash types (MD5, SHA-1, SHA-256, bcrypt).
⚠️ Ethical Use Warning: This tool is for learning and authorized security testing only. Unauthorized use is illegal and unethical. Always obtain explicit permission before testing systems.
Features

Dictionary Attack: Crack passwords using a wordlist with optional mangling rules.
Brute Force Attack: Try all combinations within a specified character set and length.
Multi-Threading: Faster cracking with parallel processing.
Supported Hashes: MD5, SHA-1, SHA-256, bcrypt.
User-Friendly: Progress bars, colored logs, and detailed output.
Extensible: Easily add new hash types or attack modes.

Installation

Clone the repository:git clone https://github.com/<your-username>/ThunderCrack.git
cd ThunderCrack


Install dependencies:pip install -r requirements.txt



Usage
Run the tool with:
python thundercrack.py --hash <target_hash> --hash-type <type> [options]

Examples

Dictionary attack with wordlist:python thundercrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --hash-type md5 --wordlist wordlists/sample_wordlist.txt


Dictionary attack with mangling rules:python thundercrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --hash-type md5 --wordlist wordlists/sample_wordlist.txt --rules


Brute force attack:python thundercrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --hash-type md5 --brute-force --max-length 4 --charset abc123



Options

--hash: Target hash to crack (required).
--hash-type: Hash algorithm (md5, sha1, sha256, bcrypt).
--wordlist: Path to wordlist file.
--rules: Apply mangling rules (e.g., append numbers, change case).
--brute-force: Enable brute force mode.
--max-length: Max password length for brute force.
--charset: Character set for brute force (e.g., abcdefghijklmnopqrstuvwxyz).
--threads: Number of threads (default: 4).

Contributing
Contributions are welcome! Please:

Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a Pull Request.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
ThunderCrack is provided for educational and ethical purposes only. The authors are not responsible for any misuse or illegal activities conducted with this tool.
