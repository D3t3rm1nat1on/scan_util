#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>

#define THREAD_COUNT 2
#define SUS_TYPE_COUNT 3
static std::atomic<size_t> error_counter{};
static std::atomic<size_t> sus_counters[SUS_TYPE_COUNT]{};
// 0 - js
// 1 - unix
// 2 - macOS

static std::atomic<int> thread_counter = THREAD_COUNT;
static std::mutex m{};
static std::condition_variable cv{};

enum sus_types
{
    NONE = -1,
    js = 0,
    unix = 1,
    maxOS = 2
};

sus_types is_sus(const std::string &str, const std::string &ext);

void threadFunction(const std::filesystem::path &path);

int main(int argc, char *argv[])
{
    std::chrono::time_point start_time{std::chrono::high_resolution_clock::now()};

    if (argc != 2)
    {
        std::cerr << "wrong param count, expected path only\n";
        return -1;
    }

    std::filesystem::path path{argv[1]};
    if (!std::filesystem::exists(path))
    {
        std::cerr << "this catalog doesn't exists\n";
        return -1;
    }

    size_t file_counter{};
    std::vector<std::thread> vec{};
    std::unique_lock<std::mutex> lock{m/*, std::defer_lock*/};
    for (const auto &iter : std::filesystem::directory_iterator{path})
    {
        cv.wait(lock, [&] {
            std::cout << "there " << thread_counter << " threads ready" << std::endl;
            return thread_counter > 0;
        });
        ++file_counter;
        --thread_counter;
        vec.emplace_back(std::thread(threadFunction, iter.path()));
    }
//    std::this_thread::sleep_for(std::chrono::seconds(5));
    for (auto &thr : vec)
        thr.join();

    auto duration{std::chrono::high_resolution_clock::now() - start_time};
    auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

    printf("========== Scan result ==========\n");
    printf("Processed files: %zu\n", file_counter);
    printf("JS detects: %zu\n", sus_counters[js].load());
    printf("Unix detects: %zu\n", sus_counters[unix].load());
    printf("macOS detects: %zu\n", sus_counters[maxOS].load());
    printf("Errors: %zu\n", error_counter.load());
    printf("Exection time: %02llds:%02lldms:%02lldus\n", duration_s, duration_ms, duration_us);
    std::cout << "=================================\n" << std::endl;
}


sus_types is_sus(const std::string &str, const std::string &ext)
{
    static const std::string js_string = "<script>evil_script()</script>";
    static const std::string unix_string = "rm -rf ~/Document";
    static const std::string macOS_string = "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")";

    if (ext == ".js" && str.find(js_string) != -1)
        return sus_types::js;

    if (str.find(unix_string) != -1)
        return sus_types::unix;

    if (str.find(macOS_string) != -1)
        return sus_types::maxOS;

    return NONE;
}

void threadFunction(const std::filesystem::path &path)
{
    std::cerr << "thread started: " << std::this_thread::get_id() << std::endl;

    std::ifstream file{path};

    if (!file.is_open())
    {
        ++error_counter;
        ++thread_counter;
        return;
    }

    std::string line;
    auto extension = path.extension().string();
    while (getline(file, line))
    {
        auto result = is_sus(line, extension);
        if (result == NONE)
            continue;

        ++sus_counters[result];
        break;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    ++thread_counter;
    std::cout << "thread ended: " << std::this_thread::get_id() << ", now " << thread_counter << " threads available" << std::endl;
    cv.notify_all();
}
