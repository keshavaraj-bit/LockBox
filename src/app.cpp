#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <limits>
#include <cstring>
#include <random>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

using namespace std;


//      SHA-256 Hashing

class SHA256 {
private:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;

    const static uint32 sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);

public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = (256/8);

private:
    void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    uint32 m_h[8];
    
    static uint32 rotr(uint32 x, uint32 n) {
        return (x >> n) | (x << (32 - n));
    }
    
    static uint32 ch(uint32 x, uint32 y, uint32 z) {
        return (x & y) ^ (~x & z);
    }
    
    static uint32 maj(uint32 x, uint32 y, uint32 z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32 f1(uint32 x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static uint32 f2(uint32 x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static uint32 f3(uint32 x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static uint32 f4(uint32 x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    static void uint32ToBigEndian(uint32 n, unsigned char* str) {
        str[0] = (n >> 24) & 0xff;
        str[1] = (n >> 16) & 0xff;
        str[2] = (n >> 8) & 0xff;
        str[3] = n & 0xff;
    }
};

const SHA256::uint32 SHA256::sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256::init() {
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len) {
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    
    memcpy(&m_block[m_len], message, rem_len);
    
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb * SHA224_256_BLOCK_SIZE], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) * SHA224_256_BLOCK_SIZE;
}

void SHA256::final(unsigned char *digest) {
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));

        len_b = (m_tot_len + m_len) * 8;
    pm_len = block_nb * SHA224_256_BLOCK_SIZE;
    
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    
    // Instead of uint32ToBigEndian(len_b,...)
for (int i = 0; i < 8; i++)
    m_block[pm_len - 1 - i] = (len_b >> (8 * i)) & 0xff;

    transform(m_block, block_nb);
    
    for (unsigned int i = 0; i < 8; i++) {
        uint32ToBigEndian(m_h[i], digest + (i * 4));
    }
}

void SHA256::transform(const unsigned char *message, unsigned int block_nb) {
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    
    for (unsigned int i = 0; i < block_nb; i++) {
        sub_block = message + (i * SHA224_256_BLOCK_SIZE);
        
        for (unsigned int j = 0; j < 16; j++) {
            w[j] = (sub_block[j*4] << 24) | (sub_block[j*4+1] << 16) | 
                   (sub_block[j*4+2] << 8) | (sub_block[j*4+3]);
        }
        
        for (unsigned int j = 16; j < 64; j++) {
            w[j] = f4(w[j-2]) + w[j-7] + f3(w[j-15]) + w[j-16];
        }
        
        for (unsigned int j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        
        for (unsigned int j = 0; j < 64; j++) {
            t1 = wv[7] + f2(wv[4]) + ch(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
            t2 = f1(wv[0]) + maj(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        
        for (unsigned int j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}

string sha256(const string& input) {
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest, 0, SHA256::DIGEST_SIZE);

    SHA256 ctx;
    ctx.init();
    ctx.update((unsigned char*)input.c_str(), input.length());
    ctx.final(digest);

    char buf[2 * SHA256::DIGEST_SIZE + 1];
    buf[2 * SHA256::DIGEST_SIZE] = 0;
    for (unsigned int i = 0; i < SHA256::DIGEST_SIZE; i++) {
        sprintf(buf + i * 2, "%02x", digest[i]);
    }
    return string(buf);
}

//      Utility Functions
class StringUtils {
public:
    static string toHex(const string& input) {
        static const char hex_digits[] = "0123456789ABCDEF";
        string output;
        output.reserve(input.length() * 2);
        for (unsigned char c : input) {
            output.push_back(hex_digits[c >> 4]);
            output.push_back(hex_digits[c & 15]);
        }
        return output;
    }

    static string fromHex(const string& hex) {
        string output;
        output.reserve(hex.length() / 2);
        for (size_t i = 0; i < hex.length(); i += 2) {
            string byteString = hex.substr(i, 2);
            char byte = (char)strtol(byteString.c_str(), nullptr, 16);
            output.push_back(byte);
        }
        return output;
    }

    static bool fileExists(const string& filename) {
        ifstream file(filename, ios::binary);
        return file.good();
    }
};


//      Auth Manager

class AuthManager {
private:
    string masterKeyFile;

public:
    AuthManager() : masterKeyFile("master.key") {}

    bool isFirstTimeSetup() {
        return !StringUtils::fileExists(masterKeyFile);
    }

    bool setMasterPassword(const string& password) {
        if (password.length() < 8) {
            cout << "❌ Master password must be at least 8 characters long.\n";
            return false;
        }

        string hashed = sha256(password);
        ofstream file(masterKeyFile, ios::binary);
        if (!file) {
            cout << "❌ Error creating master key file.\n";
            return false;
        }
        file << hashed;
        file.close();
        cout << "✅ Master password set successfully!\n";
        return true;
    }

    bool verifyMasterPassword(const string& password) {
        ifstream file(masterKeyFile, ios::binary);
        if (!file) {
            cout << "❌ Master key file not found.\n";
            return false;
        }

        string storedHash;
        file >> storedHash;
        file.close();

        string inputHash = sha256(password);
        return storedHash == inputHash;
    }
};


//      Crypto Utilities

class CryptoUtils {
public:
    static string xorEncryptDecrypt(const string& data, const string& key) {
        string result = data;
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ key[i % key.size()];
        }
        return result;
    }

    static string generateKeyFromPassword(const string& password, size_t length) {
        string key;
        key.reserve(length);
        
        // Use SHA-256 hash of password as base key material
        string hash = sha256(password);
        
        // Extend the key to required length by re-hashing with salt
        for (size_t i = 0; i < length; ++i) {
            string salted = hash + to_string(i);
            key += sha256(salted)[i % SHA256::DIGEST_SIZE];
        }
        
        return key;
    }
};


//      Password Entry

struct PasswordEntry {
    string website;
    string username;
    string password;

    string serialize() const {
        return website + "|" + username + "|" + password;
    }

    static PasswordEntry deserialize(const string& data) {
        PasswordEntry entry;
        size_t pos1 = data.find('|');
        size_t pos2 = data.find('|', pos1 + 1);
        
        if (pos1 != string::npos && pos2 != string::npos) {
            entry.website = data.substr(0, pos1);
            entry.username = data.substr(pos1 + 1, pos2 - pos1 - 1);
            entry.password = data.substr(pos2 + 1);
        }
        
        return entry;
    }
};


//      Password Manager

class PasswordManager {
private:
    string vaultFile;
    string masterPassword;

public:
    PasswordManager(const string& password) : vaultFile("vault.dat"), masterPassword(password) {}

    string generateStrongPassword(int length = 16) {
        const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowercase = "abcdefghijklmnopqrstuvwxyz";
        const string numbers = "0123456789";
        const string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        
        const string all_chars = uppercase + lowercase + numbers + symbols;
        const int all_size = all_chars.size();
        
        srand(time(nullptr));
        string password;
        
        // Ensure at least one character from each category
        password += uppercase[rand() % uppercase.size()];
        password += lowercase[rand() % lowercase.size()];
        password += numbers[rand() % numbers.size()];
        password += symbols[rand() % symbols.size()];
        
        // Fill the rest with random characters
        for (int i = 4; i < length; ++i) {
            password += all_chars[rand() % all_size];
        }
        
        // Shuffle the password
        shuffle(password.begin(), password.end(), std::mt19937(std::random_device{}()));
        
        return password;
    }

    void savePassword(const PasswordEntry& entry) {
        vector<PasswordEntry> entries = loadAllPasswords();
        entries.push_back(entry);
        saveAllPasswords(entries);
    }

    vector<PasswordEntry> loadAllPasswords() {
        vector<PasswordEntry> entries;
        
        ifstream file(vaultFile, ios::binary);
        if (!file) return entries;

        string encryptedData((istreambuf_iterator<char>(file)), 
                                 istreambuf_iterator<char>());
        file.close();

        if (encryptedData.empty()) return entries;

        string decryptedData = CryptoUtils::xorEncryptDecrypt(
            encryptedData, 
            CryptoUtils::generateKeyFromPassword(masterPassword, encryptedData.size())
        );

        // Parse decrypted data
        stringstream ss(decryptedData);
        string line;
        while (getline(ss, line)) {
            if (!line.empty()) {
                entries.push_back(PasswordEntry::deserialize(line));
            }
        }

        return entries;
    }

    void deletePassword(int index) {
        vector<PasswordEntry> entries = loadAllPasswords();
        if (index >= 0 && index < (int)entries.size()) {
            entries.erase(entries.begin() + index);
            saveAllPasswords(entries);
            cout << "✅ Password deleted successfully!\n";
        } else {
            cout << "❌ Invalid index!\n";
        }
    }

    void displayPasswords() {
        vector<PasswordEntry> entries = loadAllPasswords();
        if (entries.empty()) {
            cout << "📭 No passwords stored in vault.\n";
            return;
        }

        cout << "\n📋 Stored Passwords:\n";
        cout << "========================================\n";
        for (size_t i = 0; i < entries.size(); ++i) {
            cout << i + 1 << ". Website: " << entries[i].website 
                      << " | Username: " << entries[i].username 
                      << " | Password: " << entries[i].password << "\n";
        }
        cout << "========================================\n";
    }

private:
    void saveAllPasswords(const vector<PasswordEntry>& entries) {
        string data;
        for (const auto& entry : entries) {
            data += entry.serialize() + "\n";
        }

        string encryptedData = CryptoUtils::xorEncryptDecrypt(
            data, 
            CryptoUtils::generateKeyFromPassword(masterPassword, data.size())
        );

        ofstream file(vaultFile, ios::binary);
        file << encryptedData;
        file.close();
    }
};


//      File Vault

class FileVault {
private:
    string masterPassword;

public:
    FileVault(const string& password) : masterPassword(password) {}

    bool encryptFile(const string& filename) {
        ifstream inputFile(filename, ios::binary);
        if (!inputFile) {
            cout << "❌ Error: Cannot open file '" << filename << "'\n";
            return false;
        }

        string content((istreambuf_iterator<char>(inputFile)), 
                           istreambuf_iterator<char>());
        inputFile.close();

        string encryptedContent = CryptoUtils::xorEncryptDecrypt(
            content, 
            CryptoUtils::generateKeyFromPassword(masterPassword, content.size())
        );

        string outputFilename = filename + ".lock";
        ofstream outputFile(outputFilename, ios::binary);
        if (!outputFile) {
            cout << "❌ Error creating encrypted file.\n";
            return false;
        }

        outputFile << encryptedContent;
        outputFile.close();

        cout << "✅ File encrypted successfully: " << outputFilename << "\n";
        return true;
    }

    bool decryptFile(const string& encryptedFilename) {
        if (encryptedFilename.length() <= 6 || 
            encryptedFilename.substr(encryptedFilename.length() - 5) != ".lock") {
            cout << "❌ Error: File must have .lock extension\n";
            return false;
        }

        ifstream inputFile(encryptedFilename, ios::binary);
        if (!inputFile) {
            cout << "❌ Error: Cannot open encrypted file '" << encryptedFilename << "'\n";
            return false;
        }

        string encryptedContent((istreambuf_iterator<char>(inputFile)), 
                                   istreambuf_iterator<char>());
        inputFile.close();

        string decryptedContent = CryptoUtils::xorEncryptDecrypt(
            encryptedContent, 
            CryptoUtils::generateKeyFromPassword(masterPassword, encryptedContent.size())
        );

        string outputFilename = encryptedFilename.substr(0, encryptedFilename.length() - 5);
        ofstream outputFile(outputFilename, ios::binary);
        if (!outputFile) {
            cout << "❌ Error creating decrypted file.\n";
            return false;
        }

        outputFile << decryptedContent;
        outputFile.close();

        cout << "✅ File decrypted successfully: " << outputFilename << "\n";
        return true;
    }
};


//      User Interface

class LockBoxUI {
private:
    AuthManager authManager;
    string masterPassword;
    PasswordManager* passwordManager;
    FileVault* fileVault;

    void displayBanner() {
        cout << "\n";
        cout << "========================================\n";
        cout << "           LockBox v1.0\n";
        cout << "     Secure Password & File Vault\n";
        cout << "========================================\n";
    }

    void displayMainMenu() {
        cout << "\n🔐 Main Menu:\n";
        cout << "1. Generate New Password\n";
        cout << "2. View Saved Passwords\n";
        cout << "3. Delete Password\n";
        cout << "4. Encrypt File\n";
        cout << "5. Decrypt File\n";
        cout << "6. Exit\n";
        cout << "Choose an option (1-6): ";
    }

    void handleGeneratePassword() {
        cout << "\n🎲 Password Generator\n";
        cout << "Enter password length (12-32, default 16): ";
        
        int length = 16;
        string input;
        getline(cin, input);
        
        if (!input.empty()) {
            try {
                length = stoi(input);
                if (length < 12 || length > 32) {
                    cout << "⚠️  Length must be between 12-32. Using default 16.\n";
                    length = 16;
                }
            } catch (...) {
                cout << "⚠️  Invalid input. Using default length 16.\n";
            }
        }

        string password = passwordManager->generateStrongPassword(length);
        cout << "🔑 Generated Password: " << password << "\n";

        cout << "\nSave this password to vault? (y/n): ";
        string choice;
        getline(cin, choice);

        if (choice == "y" || choice == "Y") {
            PasswordEntry entry;
            cout << "Enter website: ";
            getline(cin, entry.website);
            cout << "Enter username: ";
            getline(cin, entry.username);
            entry.password = password;

            passwordManager->savePassword(entry);
            cout << "✅ Password saved to vault!\n";
        }
    }

    void handleViewPasswords() {
        passwordManager->displayPasswords();
    }

    void handleDeletePassword() {
        vector<PasswordEntry> entries = passwordManager->loadAllPasswords();
        if (entries.empty()) {
            cout << "📭 No passwords to delete.\n";
            return;
        }

        passwordManager->displayPasswords();
        cout << "Enter the number of password to delete: ";
        
        string input;
        getline(cin, input);
        
        try {
            int index = stoi(input) - 1;
            passwordManager->deletePassword(index);
        } catch (...) {
            cout << "❌ Invalid input!\n";
        }
    }

    void handleEncryptFile() {
        cout << "Enter filename to encrypt: ";
        string filename;
        getline(cin, filename);
        
        if (fileVault->encryptFile(filename)) {
            cout << "✅ Encryption completed successfully!\n";
        } else {
            cout << "❌ Encryption failed!\n";
        }
    }

    void handleDecryptFile() {
        cout << "Enter encrypted filename (.lock): ";
        string filename;
        getline(cin, filename);
        
        if (fileVault->decryptFile(filename)) {
            cout << "✅ Decryption completed successfully!\n";
        } else {
            cout << "❌ Decryption failed!\n";
        }
    }

public:
    LockBoxUI() : passwordManager(nullptr), fileVault(nullptr) {}

    ~LockBoxUI() {
        delete passwordManager;
        delete fileVault;
    }

    void run() {
        displayBanner();

        // First-time setup or authentication
        if (authManager.isFirstTimeSetup()) {
            cout << "\n👋 Welcome to LockBox!\n";
            cout << "Let's set up your master password.\n";
            
            while (true) {
                cout << "Enter master password (min 8 characters): ";
                getline(cin, masterPassword);
                
                if (authManager.setMasterPassword(masterPassword)) {
                    break;
                }
            }
        } else {
            cout << "\n🔐 Authentication Required\n";
            int attempts = 3;
            while (attempts > 0) {
                cout << "Enter master password (" << attempts << " attempts remaining): ";
                getline(cin, masterPassword);
                
                if (authManager.verifyMasterPassword(masterPassword)) {
                    cout << "✅ Authentication successful!\n";
                    break;
                } else {
                    cout << "❌ Invalid password!\n";
                    attempts--;
                }
            }
            
            if (attempts == 0) {
                cout << "🚫 Too many failed attempts. Exiting...\n";
                return;
            }
        }

        // Initialize managers
        passwordManager = new PasswordManager(masterPassword);
        fileVault = new FileVault(masterPassword);

        // Main application loop
        bool running = true;
        while (running) {
            displayMainMenu();
            
            string choice;
            getline(cin, choice);

            if (choice == "1") {
                handleGeneratePassword();
            } else if (choice == "2") {
                handleViewPasswords();
            } else if (choice == "3") {
                handleDeletePassword();
            } else if (choice == "4") {
                handleEncryptFile();
            } else if (choice == "5") {
                handleDecryptFile();
            } else if (choice == "6") {
                cout << "👋 Thank you for using LockBox. Goodbye!\n";
                running = false;
            } else {
                cout << "❌ Invalid option. Please try again.\n";
            }
        }
    }
};


//      Main Function

int main() {
    try {
        LockBoxUI app;
        app.run();
    } catch (const exception& e) {
        cerr << "💥 Unexpected error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}