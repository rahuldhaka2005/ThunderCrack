import hashlib
import bcrypt
import argparse
import threading
import queue
import time
import logging
import itertools
import string
from typing import List, Optional, Callable
from tqdm import tqdm
import coloredlogs

# Setup logging with colored output
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger, fmt='%(asctime)s %(levelname)s %(message)s')

class ThunderCrack:
    def __init__(self, hash_type: str, num_threads: int = 4):
        self.hash_type = hash_type.lower()
        self.num_threads = num_threads
        self.found = False
        self.result = None
        self.queue = queue.Queue()
        self.supported_hashes = {
            'md5': lambda x: hashlib.md5(x.encode()).hexdigest(),
            'sha1': lambda x: hashlib.sha1(x.encode()).hexdigest(),
            'sha256': lambda x: hashlib.sha256(x.encode()).hexdigest(),
            'bcrypt': lambda x: bcrypt.hashpw(x.encode(), bcrypt.gensalt()).decode()
        }

    def hash_password(self, password: str) -> str:
        """Generate hash of a password using specified algorithm."""
        if self.hash_type not in self.supported_hashes:
            raise ValueError(f"Unsupported hash type: {self.hash_type}. Supported: {list(self.supported_hashes.keys())}")
        return self.supported_hashes[self.hash_type](password)

    def apply_rules(self, word: str) -> List[str]:
        """Apply mangling rules to a word (e.g., append numbers, change case)."""
        variations = [word, word.upper(), word.lower(), word.capitalize()]
        for i in range(10):
            variations.append(word + str(i))
            variations.append(str(i) + word)
        return variations

    def dictionary_attack(self, target_hash: str, wordlist: List[str], use_rules: bool = False):
        """Perform dictionary attack with optional mangling rules."""
        logger.info("Starting dictionary attack...")
        start_time = time.time()

        def worker():
            while not self.queue.empty() and not self.found:
                word = self.queue.get()
                candidates = self.apply_rules(word.strip()) if use_rules else [word.strip()]
                for candidate in candidates:
                    if self.hash_type == 'bcrypt':
                        if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
                            self.found = True
                            self.result = candidate
                            break
                    else:
                        if self.hash_password(candidate) == target_hash:
                            self.found = True
                            self.result = candidate
                            break
                self.queue.task_done()

        # Fill queue with words
        for word in wordlist:
            self.queue.put(word)

        # Start threads
        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # Wait for completion
        for t in threads:
            t.join()

        if self.found:
            logger.info(f"Password found: {self.result} (Time: {time.time() - start_time:.2f}s)")
        else:
            logger.warning(f"Dictionary attack failed (Time: {time.time() - start_time:.2f}s)")
        return self.result

    def brute_force_attack(self, target_hash: str, max_length: int, charset: str):
        """Perform brute force attack with specified charset and max length."""
        logger.info("Starting brute force attack...")
        start_time = time.time()

        def worker(length: int):
            for guess in itertools.product(charset, repeat=length):
                if self.found:
                    break
                guess = ''.join(guess)
                if self.hash_type == 'bcrypt':
                    if bcrypt.checkpw(guess.encode(), target_hash.encode()):
                        self.found = True
                        self.result = guess
                        break
                else:
                    if self.hash_password(guess) == target_hash:
                        self.found = True
                        self.result = guess
                        break

        # Start threads for each length
        threads = []
        for length in range(1, max_length + 1):
            t = threading.Thread(target=worker, args=(length,))
            t.start()
            threads.append(t)

        # Progress bar
        with tqdm(total=max_length, desc="Brute force progress") as pbar:
            for t in threads:
                t.join()
                pbar.update(1)

        if self.found:
            logger.info(f"Password found: {self.result} (Time: {time.time() - start_time:.2f}s)")
        else:
            logger.warning(f"Brute force attack failed (Time: {time.time() - start_time:.2f}s)")
        return self.result

def load_wordlist(file_path: str) -> List[str]:
    """Load words from a wordlist file."""
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        logger.error(f"Wordlist file '{file_path}' not found.")
        return []

def main():
    parser = argparse.ArgumentParser(description="ThunderCrack: A powerful password cracker")
    parser.add_argument("--hash", required=True, help="Target hash to crack")
    parser.add_argument("--hash-type", default="md5", choices=['md5', 'sha1', 'sha256', 'bcrypt'], help="Hash type")
    parser.add_argument("--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("--rules", action="store_true", help="Apply mangling rules in dictionary attack")
    parser.add_argument("--brute-force", action="store_true", help="Enable brute force attack")
    parser.add_argument("--max-length", type=int, default=4, help="Max password length for brute force")
    parser.add_argument("--charset", default=string.ascii_lowercase, help="Character set for brute force")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads")

    args = parser.parse_args()

    cracker = ThunderCrack(args.hash_type, args.threads)

    # Dictionary attack
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if wordlist:
            result = cracker.dictionary_attack(args.hash, wordlist, args.rules)
            if result:
                return

    # Brute force attack
    if args.brute_force:
        result = cracker.brute_force_attack(args.hash, args.max_length, args.charset)
        if result:
            return

    logger.error("No password found. Try a larger wordlist, rules, or increase max-length.")

if __name__ == "__main__":
    main()
