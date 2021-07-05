#include <filesystem>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include <condition_variable>
#include <atomic>

#define THREAD_COUNT 3
#define SUS_TYPE_COUNT 3

enum suspicious_types_enum
{
    NONE = -1,
    js = 0,
    unix = 1,
    maxOS = 2
};

suspicious_types_enum suspicion_check(const std::string &str, const std::string &ext);
void check_file(const std::filesystem::path &path);

static std::atomic<size_t> error_counter{};
static std::atomic<size_t> suspicious_files_counters[SUS_TYPE_COUNT]{};
// 0 - js
// 1 - unix
// 2 - macOS
static std::atomic<int> available_threads_counter = THREAD_COUNT;
static std::condition_variable cv{};

int main(int argc, char *argv[])
{
    printf("");
    auto start_time{std::chrono::high_resolution_clock::now()};
    size_t file_counter{};
    std::mutex m{};
    std::vector<std::thread> thread_vector{};
    std::unique_lock<std::mutex> lock{m};

    if (argc != 2)
    {
        fprintf(stderr, "wrong param count, expected path only\n");
        return -1;
    }

    std::filesystem::path path{argv[1]};
    if (!std::filesystem::exists(path))
    {
        fprintf(stderr, "directory doesn't exist: %s\n", path.string().c_str());
        return -1;
    }

    if (!std::ifstream{path}.is_open())
    {
        fprintf(stderr, "operation not permitted for directory: %s\n", path.string().c_str());
        return 6;
    }

    for (const auto &iter : std::filesystem::directory_iterator{path})
    {
        cv.wait(lock, [&] {
            return available_threads_counter > 0;
        });
        ++file_counter;
        --available_threads_counter;
        thread_vector.emplace_back(std::thread(check_file, iter.path()));
    }

    for (auto &thr : thread_vector)
        thr.join();

    auto duration{std::chrono::high_resolution_clock::now() - start_time};
    auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

    printf("========== Scan result ==========\n");
    printf("Processed files: %zu\n", file_counter);
    printf("JS detects: %zu\n", suspicious_files_counters[js].load());
    printf("Unix detects: %zu\n", suspicious_files_counters[unix].load());
    printf("macOS detects: %zu\n", suspicious_files_counters[maxOS].load());
    printf("Errors: %zu\n", error_counter.load());
    printf("Execution time: %02llds:%02lldms:%02lldus\n", duration_s, duration_ms, duration_us);
    printf("=================================\n");
}

suspicious_types_enum suspicion_check(const std::string &str, const std::string &ext)
{
    static const std::string js_string = "<script>evil_script()</script>";
    static const std::string unix_string = "rm -rf ~/Document";
    static const std::string macOS_string = "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")";

    if (ext == ".js" && str.find(js_string) != -1)
        return suspicious_types_enum::js;

    if (str.find(unix_string) != -1)
        return suspicious_types_enum::unix;

    if (str.find(macOS_string) != -1)
        return suspicious_types_enum::maxOS;

    return NONE;
}

void check_file(const std::filesystem::path &path)
{
    std::ifstream file{path};

    if (!file.is_open())
    {
        ++error_counter;
        ++available_threads_counter;
        cv.notify_all();
        return;
    }

    std::string line;
    const std::string &extension = path.extension().string();
    while (getline(file, line))
    {
        auto result = suspicion_check(line, extension);
        if (result == NONE)
            continue;

        ++suspicious_files_counters[result];
        break;
    }

    ++available_threads_counter;
    cv.notify_all();
}