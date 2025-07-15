#include <iostream>
#include <set>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <random>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <map>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <future>
#include <filesystem>
#include <sstream>
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BOLD    "\033[1m"

// ---- Mini SHA256 (public domain, für Hash-Feature) ----
namespace mini_sha256 {
    typedef uint8_t  uint8;
    typedef uint32_t uint32;
    typedef uint64_t uint64;
    class SHA256 {
    public:
        SHA256() { reset(); }
        void update(const uint8* data, size_t len) {
            for (size_t i = 0; i < len; ++i) {
                data_[datalen_++] = data[i];
                if (datalen_ == 64) {
                    transform();
                    bitlen_ += 512;
                    datalen_ = 0;
                }
            }
        }
        void update(const std::vector<char>& data, size_t len) {
            update(reinterpret_cast<const uint8*>(data.data()), len);
        }
        void final(uint8 hash[32]) {
            size_t i = datalen_;
            if (datalen_ < 56) {
                data_[i++] = 0x80;
                while (i < 56) data_[i++] = 0x00;
            } else {
                data_[i++] = 0x80;
                while (i < 64) data_[i++] = 0x00;
                transform();
                std::memset(data_, 0, 56);
            }
            bitlen_ += datalen_ * 8;
            data_[63] = bitlen_;
            data_[62] = bitlen_ >> 8;
            data_[61] = bitlen_ >> 16;
            data_[60] = bitlen_ >> 24;
            data_[59] = bitlen_ >> 32;
            data_[58] = bitlen_ >> 40;
            data_[57] = bitlen_ >> 48;
            data_[56] = bitlen_ >> 56;
            transform();
            for (i = 0; i < 4; ++i) {
                for (int j = 0; j < 8; ++j) {
                    hash[i + j * 4] = (state_[j] >> (24 - i * 8)) & 0x000000ff;
                }
            }
        }
        static std::string to_hex(const uint8 hash[32]) {
            std::ostringstream oss;
            for (int i = 0; i < 32; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            return oss.str();
        }
    private:
        uint8 data_[64];
        uint32 datalen_;
        uint64 bitlen_;
        uint32 state_[8];
        static constexpr uint32 k_[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        void reset() {
            datalen_ = 0;
            bitlen_ = 0;
            state_[0] = 0x6a09e667;
            state_[1] = 0xbb67ae85;
            state_[2] = 0x3c6ef372;
            state_[3] = 0xa54ff53a;
            state_[4] = 0x510e527f;
            state_[5] = 0x9b05688c;
            state_[6] = 0x1f83d9ab;
            state_[7] = 0x5be0cd19;
        }
        static uint32 rotr(uint32 x, uint32 n) { return (x >> n) | (x << (32 - n)); }
        void transform() {
            uint32 m[64], a, b, c, d, e, f, g, h, t1, t2;
            for (uint32 i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = (data_[j] << 24) | (data_[j + 1] << 16) | (data_[j + 2] << 8) | (data_[j + 3]);
            for (uint32 i = 16; i < 64; ++i)
                m[i] = (rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10)) + m[i - 7] +
                       (rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3)) + m[i - 16];
            a = state_[0]; b = state_[1]; c = state_[2]; d = state_[3];
            e = state_[4]; f = state_[5]; g = state_[6]; h = state_[7];
            for (uint32 i = 0; i < 64; ++i) {
                t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k_[i] + m[i];
                t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
            state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
        }
    };
    inline std::string hash_file(const std::string& filename) {
        SHA256 sha;
        std::ifstream file(filename, std::ios::binary);
        std::vector<char> buf(8192);
        while (file) {
            file.read(buf.data(), buf.size());
            std::streamsize n = file.gcount();
            if (n > 0) sha.update(buf, n);
        }
        uint8 hash[32];
        sha.final(hash);
        return SHA256::to_hex(hash);
    }
}
// ---- Ende Mini SHA256 ----

struct Task {
    std::string filename;
    std::size_t size;
};

// --- STATISTIK-STRUKTUR ---
struct FileStat {
    std::string filename;
    double write_time_sec;
    std::size_t size;
    bool success;
    std::string error_msg;
};

std::vector<FileStat> file_stats;
std::mutex file_stats_mtx;

std::string random_string(std::size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static thread_local std::mt19937_64 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(0, sizeof(chars) - 2);
    std::string s;
    for (std::size_t i = 0; i < len; ++i) s += chars[dis(gen)];
    return s;
}

std::string get_charset(const std::string& content_type) {
    if (content_type == "ascii")
        return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (content_type == "digit")
        return "0123456789";
    if (content_type == "german")
        return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZäöüÄÖÜß";
    if (content_type == "hex")
        return "0123456789abcdef";
    if (content_type == "bin")
        return "";
    if (content_type == "special")
        return "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
}

void fill_content(std::vector<char>& buffer, std::size_t n, const std::string& content_type) {
    static thread_local std::mt19937_64 gen(std::random_device{}());
    if (content_type == "bin") {
        std::size_t i = 0;
        for (; i + 8 <= n; i += 8) {
            uint64_t rnd = gen();
            std::memcpy(buffer.data() + i, &rnd, 8);
        }
        if (i < n) {
            uint64_t rnd = gen();
            std::memcpy(buffer.data() + i, &rnd, n - i);
        }
    } else {
        std::string charset = get_charset(content_type);
        std::uniform_int_distribution<> dis(0, charset.size() - 1);
        for (std::size_t i = 0; i < n; ++i)
            buffer[i] = charset[dis(gen)];
    }
}

#ifdef __linux__
bool fill_urandom(std::vector<char>& buffer, std::size_t n, int& urandom_fd) {
    std::size_t total = 0;
    while (total < n) {
        ssize_t res = read(urandom_fd, buffer.data() + total, n - total);
        if (res <= 0) return false;
        total += res;
    }
    return true;
}
#endif

std::ofstream logfile;
bool debug = false;
#define DEBUG_OUT(msg) do { if (debug) { std::cerr << "[DEBUG] " << msg << std::endl; if (logfile.is_open()) logfile << "[DEBUG] " << msg << std::endl; } } while(0)
void log(const std::string& msg) {
    std::cerr << msg << std::endl;
    if (logfile.is_open()) logfile << msg << std::endl;
}

void log_error(const std::string& msg) {
    std::cerr << COLOR_RED << COLOR_BOLD << "[ERROR] " << msg << COLOR_RESET << std::endl;
}

// Warnungsausgabe (gelb)
void log_warning(const std::string& msg) {
    std::cerr << COLOR_YELLOW << "[WARNING] " << msg << COLOR_RESET << std::endl;
}

void print_help(const char* progname) {
    std::cout <<
        "File Generator\n"
        "Creates any number of files with desired content and size.\n\n"
        "Usage:\n"
        "  " << progname << " --path <path> --basename <name> --count <number> --size <kb|MB|GB> [--minsize <kb|MB|GB>] [--maxsize <kb|MB|GB>] --mode <r/z/u> [--threads <n>] [--blocksize <kb>] [--ext <.ext>] [--start <n>] [--random-names] [--dry-run] [--hash] [--content-type <ascii|digit|german|hex|bin|special>] [--async] [--pattern <str>] [--cleanup] [--log <file>] [--json] [--debug]\n"
        "Parameters can be specified in any order.\n"
        "Example:\n"
        "  " << progname << " --path /destination/path --basename test --mode r --count 10 --size 400M --threads 10 --blocksize 1k --ext .bin --start 42 --random-names --hash --content-type ascii --async --cleanup\n\n"
        "Short options:\n"
        "  -p  --path         Target directory\n"
        "  -b  --basename     Base name of the files\n"
        "  -c  --count        Number of files (file count limit in Windows and Linux --> error)\n"
        "  -s  --size         File size (e.g. 1K, 1M, 2G)\n"
        "  --minsize          Minimum file size (range, like --size)\n"
        "  --maxsize          Maximum file size (range, like --size)\n"
        "  -m  --mode         'r' for random (Windows), 'z' for zeros, 'u' for /dev/urandom (Linux)\n"
        "  -t  --threads      (optional) Number of threads\n"
        "  -B  --blocksize    (optional) Block size in KB (program internal, the amount of data being buffered) (default: 4096 = 4MB)\n"
        "  -e  --ext          (optional) File extension, e.g. .bin\n"
        "  -S  --start        (optional) Start index for file names (e.g. start from 3)\n"
        "  --random-names     (optional) Random file names\n"
        "  --dry-run          (optional) Only display what would be done\n"
        "  --hash             (optional) Output SHA256 hash after creation\n"
        "  --content-type     (optional) ascii, digit, german, hex, bin, special\n"
        "  --async            (optional) Asynchronous writing\n"
        "  --pattern          (optional) Pattern string to be written cyclically into the file\n"
        "  --cleanup          (optional) Delete all generated files after test run\n"
        "  --log <file>       (optional) Log file for actions and errors, in combination with debug\n"
        "  --json             (optional) Output statistics as JSON\n"
        "  --debug            (optional) Additional debug output\n"
        "  -h  --help         Show this help message\n"
        "  --histogram        (optional) Show file size histogram in output\n";
}

std::size_t parse_size(const std::string& s) {
    if (s.empty()) return 0;
    char suffix = std::tolower(s.back());
    std::size_t mult = 1;
    std::string num = s;
    if (suffix == 'g') { mult = 1024 * 1024; num = s.substr(0, s.size() - 1); }
    else if (suffix == 'm') { mult = 1024; num = s.substr(0, s.size() - 1); }
    else if (suffix == 'k') { mult = 1; num = s.substr(0, s.size() - 1); }
    return std::stoull(num) * mult;
}

bool parse_args(int argc, char* argv[], std::string& path, std::string& basename, std::size_t& count, std::size_t& size_kb, std::size_t& minsize_kb, std::size_t& maxsize_kb, char& mode, int& threads_num, std::size_t& blocksize_kb, std::string& ext, std::size_t& start_index, bool& random_names, bool& dry_run, bool& hash, std::string& content_type, bool& async_mode, std::string& pattern, bool& cleanup, std::string& logfilename, bool& json, bool& debug, bool& histogram) {
    std::map<std::string, std::string> argmap;
    std::set<std::string> flagset;
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        if (key == "--help" || key == "-h") {
            print_help(argv[0]);
            exit(0);
        }
        if (key[0] == '-') {
            if ((i + 1 < argc) && argv[i + 1][0] != '-') {
                argmap[key] = argv[++i];
            } else {
                flagset.insert(key);
            }
        }
    }
    auto get = [&](const std::string& longkey, const std::string& shortkey = "") -> std::string {
        if (argmap.count(longkey)) return argmap[longkey];
        if (!shortkey.empty() && argmap.count(shortkey)) return argmap[shortkey];
        return "";
    };
    path = get("--path", "-p");
    basename = get("--basename", "-b");
    std::string scount = get("--count", "-c");
    std::string ssize  = get("--size", "-s");
    std::string sminsize = get("--minsize");
    std::string smaxsize = get("--maxsize");
    std::string smode  = get("--mode", "-m");
    std::string sthreads = get("--threads", "-t");
    std::string sblocksize = get("--blocksize", "-B");
    pattern = get("--pattern");
    ext = get("--ext", "-e");
    std::string sstart = get("--start", "-S");
    content_type = get("--content-type");
    random_names = flagset.count("--random-names");
    dry_run = flagset.count("--dry-run");
    hash = flagset.count("--hash");
    async_mode = flagset.count("--async");
    cleanup = flagset.count("--cleanup");
    logfilename = get("--log");
    json = flagset.count("--json");
    debug = flagset.count("--debug");
    histogram = flagset.count("--histogram");

    if (ext.empty()) ext = ".txt";
    if (sstart.empty()) start_index = 1;
    else start_index = std::stoull(sstart);

    if (path.empty() || basename.empty() || scount.empty() || (ssize.empty() && sminsize.empty() && smaxsize.empty()) || smode.empty()) {
        log_warning("Missing parameters! For help: --help oder -h");
        return false;
    }
    try {
        count = std::stoull(scount);
        if (!ssize.empty()) size_kb = parse_size(ssize);
        if (!sminsize.empty()) minsize_kb = parse_size(sminsize);
        if (!smaxsize.empty()) maxsize_kb = parse_size(smaxsize);
        if (size_kb > 0 && minsize_kb == 0 && maxsize_kb == 0) minsize_kb = maxsize_kb = size_kb;
        else {
            if (minsize_kb == 0) minsize_kb = maxsize_kb;
            if (maxsize_kb == 0) maxsize_kb = minsize_kb;
        }
        mode  = smode[0];
        threads_num = 0;
        if (!sthreads.empty())
            threads_num = std::stoi(sthreads);
        blocksize_kb = 4096;
        if (!sblocksize.empty())
            blocksize_kb = std::stoull(sblocksize);
    } catch (...) {
        log_warning("Invalid values for count, size, mode, threads or blocksize!");
        return false;
    }
    if (mode != 'r' && mode != 'z' && mode != 'u') {
        log_warning("Mode must be 'r' (random), 'z' (Nullen) or 'u' (/dev/urandom, nur Linux)!");
        return false;
    }
    if (count == 0 || minsize_kb == 0 || maxsize_kb == 0) {
        log_warning("Count and size must be greater than 0!");
        return false;
    }
    if (threads_num < 0) {
        log_warning("Threadcount must be greater than 0!");
        return false;
    }
    if (blocksize_kb == 0) {
        log_warning("Blocksize must be greater than 0!");
        return false;
    }
    if (minsize_kb > maxsize_kb) std::swap(minsize_kb, maxsize_kb);
    if (content_type.empty()) content_type = "bin";
    return true;
}

void create_file(const Task& task, std::size_t bufferSize, char mode, const std::string& content_type, const std::string& pattern, bool no_overwrite) {
    auto start = std::chrono::high_resolution_clock::now();
    bool success = false;
    std::string error_msg;
    
    if (no_overwrite && std::filesystem::exists(task.filename)) {
        log_warning("File already exists: " + task.filename);
        error_msg = "File already exists";
    } else {
        std::ofstream file(task.filename, std::ios::binary);
        if (!file.is_open()) {
            log_error("Couldn't open file " + task.filename);
            error_msg = "Couldn't open file";
        } else {
            std::vector<char> buffer(bufferSize, 0);
    #ifdef __linux__
            int urandom_fd = -1;
            if (mode == 'u') {
                urandom_fd = open("/dev/urandom", O_RDONLY);
                if (urandom_fd < 0) {
                    log_error("Couldn't open /dev/urandom!");
                    error_msg = "Couldn't open /dev/urandom";
                }
            }
    #endif
            std::size_t written = 0;
            while (written < task.size && error_msg.empty()) {
                std::size_t toWrite = std::min(bufferSize, task.size - written);
                if (!pattern.empty()) {
                    if (written == 0)
                        DEBUG_OUT("Pattern is used for " << task.filename << ": '" << pattern << "'");
                    for (std::size_t i = 0; i < toWrite; ++i)
                        buffer[i] = pattern[(written + i) % pattern.size()];
                } else if (mode == 'r') {
                    fill_content(buffer, toWrite, content_type);
                } else if (mode == 'z') {
                    std::fill(buffer.begin(), buffer.begin() + toWrite, '0');
    #ifdef __linux__
                } else if (mode == 'u') {
                    if (!fill_urandom(buffer, toWrite, urandom_fd)) {
                        log_error("Error on reading /dev/urandom!");
                        error_msg = "Error on reading /dev/urandom";
                        break;
                    }
    #endif
                }
                file.write(buffer.data(), static_cast<std::streamsize>(toWrite));
                if (!file) {
                    log_error("Write error on file " + task.filename);
                    error_msg = "Write error";
                    break;
                }
                written += toWrite;
            }
    #ifdef __linux__
            if (mode == 'u' && urandom_fd >= 0)
                close(urandom_fd);
    #endif
            if (error_msg.empty()) success = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double>(end - start).count();
    // Statistik speichern
    {
        std::lock_guard<std::mutex> lock(file_stats_mtx);
        file_stats.push_back({task.filename, duration, task.size, success, error_msg});
    }
}

void worker(std::queue<Task>& tasks, std::mutex& mtx, std::atomic<bool>& done, std::size_t bufferSize, char mode, const std::string& content_type, std::atomic<std::size_t>& counter, bool async_mode, const std::string& pattern, bool no_overwrite) {
    DEBUG_OUT("Worker-Thread started: " << std::this_thread::get_id());
    std::vector<std::future<void>> futures; // Sammle alle Futures

    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(mtx);
            if (tasks.empty()) {
                if (done) break;
                continue;
            }
            task = tasks.front();
            tasks.pop();
        }
        DEBUG_OUT("Worker " << std::this_thread::get_id() << " takes over Task: " << task.filename << " (" << task.size << " Bytes)");
        if (async_mode) {
            DEBUG_OUT("Async-Task for " << task.filename << " started.");
            // Starte Task asynchron und merke dir das Future
            futures.push_back(
                std::async(std::launch::async, create_file, task, bufferSize, mode, content_type, pattern, no_overwrite)
            );
        } else {
            DEBUG_OUT("Sync-Task for " << task.filename << " started.");
            create_file(task, bufferSize, mode, content_type, pattern, no_overwrite);
        }
        ++counter;
    }

    // Warte auf alle asynchron gestarteten Tasks
    if (async_mode) {
        for (auto& fut : futures) {
            fut.get();
        }
    }
}

// Hilfsfunktion für JSON-Escaping (Backslashes und Anführungszeichen)
std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (auto c : s) {
        switch (c) {
            case '\\': o << "\\\\"; break;
            case '"':  o << "\\\""; break;
            default:   o << c;
        }
    }
    return o.str();
}

int main(int argc, char* argv[]) {
    std::string path, basename, ext, content_type, pattern, logfilename;
    std::size_t count = 0, size_kb = 0, minsize_kb = 0, maxsize_kb = 0, blocksize_kb = 8192, start_index = 1;
    int threads_num = 0;
    char mode = 'z';
    bool random_names = false, dry_run = false, hash = false, async_mode = false, cleanup = false, json = false, no_overwrite = false, histogram = false;

    if (!parse_args(argc, argv, path, basename, count, size_kb, minsize_kb, maxsize_kb, mode, threads_num, blocksize_kb, ext, start_index, random_names, dry_run, hash, content_type, async_mode, pattern, cleanup, logfilename, json, debug, histogram)) {
        return 1;
    }

    if (!logfilename.empty()) logfile.open(logfilename, std::ios::app);

    if (debug) {
        std::cerr << "[DEBUG] Parameter: path=" << path << ", basename=" << basename << ", count=" << count
                  << ", minsize_kb=" << minsize_kb << ", maxsize_kb=" << maxsize_kb << ", mode=" << mode
                  << ", threads=" << threads_num << ", blocksize_kb=" << blocksize_kb << ", ext=" << ext
                  << ", start_index=" << start_index << ", random_names=" << random_names
                  << ", dry_run=" << dry_run << ", hash=" << hash << ", async_mode=" << async_mode
                  << ", cleanup=" << cleanup << ", logfilename=" << logfilename << ", json=" << json
                  << ", pattern=" << pattern << std::endl;
    }

    std::size_t bufferSize = blocksize_kb * 1024;
    try {
        std::filesystem::create_directories(path);
    } catch (...) {
        log_warning("Couldn't create folder: " + path);
        return 1;
    }

    std::queue<Task> tasks;
    std::mutex mtx;
    std::atomic<bool> done(false);
    std::atomic<std::size_t> counter(0);
    std::vector<std::string> alle_filenames;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<std::size_t> sizedist(minsize_kb, maxsize_kb);

    for (std::size_t i = 0; i < count; ++i) {
        std::string filename = path;
        if (!filename.empty() && filename.back() != '/' && filename.back() != '\\')
#ifdef _WIN32
            filename += '\\';
#else
            filename += '/';
#endif
        if (random_names)
            filename += random_string(8) + ext;
        else
            filename += basename + std::to_string(start_index + i) + ext;
        std::size_t this_size = (minsize_kb == maxsize_kb) ? minsize_kb * 1024 : sizedist(gen) * 1024;
        if (dry_run) {
            std::cout << "[Dry-Run] File: " << filename << " (" << this_size / 1024 << " KB)\n";
            continue;
        }
        tasks.push({filename, this_size});
        alle_filenames.push_back(filename);
        DEBUG_OUT("Task created: " << filename << " (" << this_size << " Bytes)");
    }

    if (dry_run) return 0;

    if (threads_num <= 0)
        threads_num = std::min(4u, std::max(1u, std::thread::hardware_concurrency()));

    std::vector<std::thread> pool;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < threads_num; ++i) {
        pool.emplace_back(worker, std::ref(tasks), std::ref(mtx), std::ref(done), bufferSize, mode, content_type, std::ref(counter), async_mode, std::ref(pattern), no_overwrite);
        DEBUG_OUT("Thread " << i << " started.");
    }

    std::size_t last_count = 0;
    auto last_time = std::chrono::high_resolution_clock::now();
    while (counter < count) {
        double percent = 100.0 * counter / count;
        auto now = std::chrono::high_resolution_clock::now();
        double speed = (counter - last_count) / std::max(0.01, (std::chrono::duration<double>(now - last_time).count()));
        std::cout << "\r[";
        int bar = static_cast<int>(percent / 2);
        std::cout << std::string(bar, '#') << std::string(50 - bar, ' ')
                << "] " << std::fixed << std::setprecision(1) << percent << "%, "
                << std::setprecision(2) << speed << " files/s" << std::flush;
        last_time = now;
        last_count = counter;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "\r[##################################################] 100.0%, " << counter << " files/s\n";
    done = true;
    for (auto& t : pool) t.join();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    double total_bytes = 0;
    for (std::size_t i = 0; i < alle_filenames.size(); ++i) {
        try {
            total_bytes += std::filesystem::file_size(alle_filenames[i]);
        } catch (...) {}
    }
    double total_mb = total_bytes / (1024.0 * 1024.0);
    double total_gb = total_mb / 1024.0;
    double mb_per_s = total_mb / elapsed.count();
    double files_per_s = (double)count / elapsed.count();

    double min_time = std::numeric_limits<double>::max();
    double max_time = 0;
    double total_time = 0;
    std::string slowest_file, fastest_file;
    std::size_t error_count = 0, success_count = 0;
    double min_size = std::numeric_limits<double>::max();
    double max_size = 0;
    double total_size = 0;

    for (const auto& stat : file_stats) {
        if (!stat.success) {
            ++error_count;
            std::cerr << COLOR_RED << COLOR_BOLD << "[ERROR] " << stat.filename << ": " << stat.error_msg << COLOR_RESET << std::endl;
            continue;
        }
        ++success_count;
        if (stat.write_time_sec < min_time) { min_time = stat.write_time_sec; fastest_file = stat.filename; }
        if (stat.write_time_sec > max_time) { max_time = stat.write_time_sec; slowest_file = stat.filename; }
        if (stat.size < min_size) min_size = stat.size;
        if (stat.size > max_size) max_size = stat.size;
        total_time += stat.write_time_sec;
        total_size += stat.size;
    }

    double avg_time = (success_count > 0) ? (total_time / success_count) : 0;
    double avg_size = (success_count > 0) ? (total_size / success_count) : 0;

    // Histogramm berechnen
    std::map<std::size_t, int> size_histogram;
    if (histogram) {
        for (const auto& stat : file_stats) {
            if (stat.success) {
                std::size_t kb = stat.size / 1024;
                size_histogram[kb]++;
            }
        }
    }


    if (hash) {
        std::cout << "\nSHA256-Hashes:\n";
        for (const auto& filename : alle_filenames) {
            std::cout << filename << ": " << mini_sha256::hash_file(filename) << "\n";
        }
    }

    if (cleanup) {
        for (const auto& fname : alle_filenames) {
            try {
                std::filesystem::remove(fname);
                DEBUG_OUT("File deleted: " << fname);
            } catch (...) {
                DEBUG_OUT("Error deleting: " << fname);
            }
        }
        log("All generated files have been deleted (--cleanup).");
    }

    if (json) {
        std::cout << std::fixed << std::setprecision(4);
        std::cout << "{\n"
            << "  \"files\": " << count << ",\n"
            << "  \"files_created\": " << success_count << ",\n"
            << "  \"errors\": " << error_count << ",\n"
            << "  \"total_mb\": " << total_mb << ",\n"
            << "  \"total_gb\": " << total_gb << ",\n"
            << "  \"blocksize_kb\": " << blocksize_kb << ",\n"
            << "  \"runtime_s\": " << elapsed.count() << ",\n"
            << "  \"mb_per_s\": " << mb_per_s << ",\n"
            << "  \"files_per_s\": " << files_per_s << ",\n"
            << "  \"min_write_time_s\": " << min_time << ",\n"
            << "  \"max_write_time_s\": " << max_time << ",\n"
            << "  \"avg_write_time_s\": " << avg_time << ",\n"
            << "  \"min_file_size_kb\": " << (min_size / 1024) << ",\n"
            << "  \"max_file_size_kb\": " << (max_size / 1024) << ",\n"
            << "  \"avg_file_size_kb\": " << (avg_size / 1024) << ",\n"
            << "  \"fastest_file\": {\n"
            << "    \"name\": \"" << escape_json(fastest_file) << "\",\n"
            << "    \"time_s\": " << min_time << "\n"
            << "  },\n"
            << "  \"slowest_file\": {\n"
            << "    \"name\": \"" << escape_json(slowest_file) << "\",\n"
            << "    \"time_s\": " << max_time << "\n"
            << "  }";
        if (histogram) {
            std::cout << ",\n  \"size_histogram_kb\": {\n";
            bool first = true;
            for (const auto& [kb, count] : size_histogram) {
                if (!first) std::cout << ",\n";
                std::cout << "    \"" << kb << "\": " << count;
                first = false;
            }
            std::cout << "\n  }";
        }
        std::cout << "\n}\n";
    } else {
        std::cout << std::fixed << std::setprecision(4);
        std::cout << "\nResult:\n";
        std::cout << "  Files Created:      " << success_count << " / " << count << "\n";
        std::cout << "  Errors:             " << error_count << "\n";
        std::cout << "  Total size:         " << total_mb << " MB (" << total_gb << " GB)\n";
        std::cout << "  Blocksize:          " << blocksize_kb << " KB (" << bufferSize << " Byte)\n";
        std::cout << "  Runtime:            " << elapsed.count() << " Sekunden\n";
        std::cout << "  Datarate:           " << mb_per_s << " MB/s\n";
        std::cout << "  Files per Second:   " << files_per_s << "\n";
        std::cout << "  Fastest file:       " << fastest_file << " (" << min_time << " s)\n";
        std::cout << "  Slowest file:       " << slowest_file << " (" << max_time << " s)\n";
        std::cout << "  Avg. write time:    " << avg_time << " s\n";
        std::cout << "  Min file size:      " << min_size / 1024 << " KB\n";
        std::cout << "  Max file size:      " << max_size / 1024 << " KB\n";
        std::cout << "  Avg. file size:     " << avg_size / 1024 << " KB\n";
        if (histogram) {
            std::cout << "  File size histogram (KB):\n";
            for (const auto& [kb, count] : size_histogram) {
                std::cout << "    " << kb << " KB: " << count << "\n";
            }
        }
    }

    if (logfile.is_open()) logfile.close();
    return 0;
}
