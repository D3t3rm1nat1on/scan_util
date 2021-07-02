#include <dirent.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <unistd.h>

enum sus_types
{
    NONE = -1,
    js,
    unix,
    maxOS
};


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
    auto start{std::chrono::high_resolution_clock::now()};
    auto time_start = clock();
    if (argc != 2)
    {
        std::cerr << "wrong param count, expected path only\n";
        return -1;
    }


    std::filesystem::path path{argv[1]};
    std::cout << argv[1] << std::endl;
    if (!std::filesystem::exists(path))
    {

        std::cerr << "this catalog doesn't exists\n";
        return -1;
    }

    size_t error_counter{};
    size_t js_counter{};
    size_t unix_counter{};
    size_t macOS_counter{};
    size_t file_counter{};
    std::string line;

    for (const auto &iter : std::filesystem::directory_iterator{path})
    {
        ++file_counter;
        std::ifstream file{iter.path()};
        if (!file.is_open())
        {
            ++error_counter;
            continue;
        }
        bool find_any = false;
        auto extension = iter.path().extension().string();
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
            }
        }
    }

    auto duration{std::chrono::high_resolution_clock::now() - start};
    auto time_end = clock();


    std::cout << "====== Scan result ======" << std::endl;
    std::cout << "Processed files: " << file_counter << std::endl;
    std::cout << "JS detects: " << js_counter << std::endl;
    std::cout << "Unix detects: " << unix_counter << std::endl;
    std::cout << "macOS detects: " << macOS_counter << std::endl;
    std::cout << "Errors: " << error_counter << std::endl;
    std::cout << "Exection time: " << ((double) time_end - (double) time_start) / (double) CLOCKS_PER_SEC << std::endl;
    printf("%.4f\n", ((double) time_start - time_end) / CLOCKS_PER_SEC);
    std::cout << (double) duration.count() / 1000000000 << std::endl;
    std::cout << "=========================\n" << std::endl;

}
