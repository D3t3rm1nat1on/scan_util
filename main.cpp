#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>

#define THREAD_COUNT 3
static std::atomic<size_t> error_counter{};
static std::atomic<size_t> js_counter{};
static std::atomic<size_t> unix_counter{};
static std::atomic<size_t> macOS_counter{};
static std::atomic<size_t> file_counter{};

static std::atomic<int> thread_counter = THREAD_COUNT;
static std::mutex m{};

enum sus_types
{
    NONE = -1,
    js,
    unix,
    maxOS
};

sus_types is_sus(const std::string &str);

void threadFunction(const std::filesystem::path &path)
{
    std::unique_lock<std::mutex> unique_lock_m(m);
    --thread_counter;
    if (thread_counter.load())
    {
        unique_lock_m.unlock();
    }

    std::ifstream file{path};

    if (!file.is_open())
    {
        ++error_counter;
        ++thread_counter;
        return;
    }

    std::string line;
    bool find_any = false;
    auto extension = path.extension().string();
    while (getline(file, line) && !find_any)
    {
        auto result = is_sus(line);
        switch (result)
        {
            case sus_types::js:
                if (extension == ".js")
                {
                    find_any = true;
                    ++js_counter;
                }
                break;
            case sus_types::maxOS:
                find_any = true;
                ++macOS_counter;
                break;
            case sus_types::unix:
                find_any = true;
                ++unix_counter;
                break;
            default:
                break;
        }
    }

    ++thread_counter;
}

sus_types is_sus(const std::string &str)
{
    static const std::string js_string = "<script>evil_script()</script>";
    static const std::string unix_string = "rm -rf ~/Document";
    static const std::string macOS_string = "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")";
    // TODO
    // проверять на JS только при разрешении .js
    if (str.find(js_string) != -1)
        return sus_types::js;

    if (str.find(unix_string) != -1)
        return sus_types::unix;

    if (str.find(macOS_string) != -1)
        return sus_types::maxOS;

    return NONE;
}


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

    std::vector<std::thread *> vec{};
    for (const auto &iter : std::filesystem::directory_iterator{path})
    {
        ++file_counter;
        auto *tmp = new std::thread(threadFunction, iter.path());
        vec.emplace_back(tmp);
    }
    for (auto thr : vec)
        if (thr->joinable())
            thr->join();

    auto duration{std::chrono::high_resolution_clock::now() - start_time};
    auto duration_s = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count() % 1000;

    printf("========== Scan result ==========\n");
    printf("Processed files: %zu\n", file_counter.load());
    printf("JS detects: %zu\n", js_counter.load());
    printf("Unix detects: %zu\n", unix_counter.load());
    printf("macOS detects: %zu\n", macOS_counter.load());
    printf("Errors: %zu\n", error_counter.load());
    printf("Exection time: %02llds:%02lldms:%02lldus\n", duration_s, duration_ms, duration_us);
    std::cout << "=================================\n" << std::endl;
}
