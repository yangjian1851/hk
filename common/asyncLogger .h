#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <ctime>
#include <condition_variable>
#include <sstream>
#include <direct.h>
#include <sys/stat.h>  // POSIX 标准

class AsyncLogger {
public:
    AsyncLogger() : exitFlag(false) {
        std::string dirPath = "log";

        // 检查目录是否存在
        struct stat info;
        if (stat(dirPath.c_str(), &info) != 0) {
            // 如果目录不存在，创建它
#ifdef _WIN32
            if (_mkdir(dirPath.c_str()) == 0) {
#else
            if (mkdir(dirPath.c_str(), 0755) == 0) {
#endif
                std::cout << "Directory created successfully: " << dirPath << std::endl;
            }
            else {
                std::cerr << "Failed to create directory: " << dirPath << std::endl;
            }
        }
        else if (info.st_mode & S_IFDIR) {
            std::cout << "Directory already exists: " << dirPath << std::endl;
        }
        else {
            std::cerr << "A file with the same name exists: " << dirPath << std::endl;
        }
        loggingThread = std::thread(&AsyncLogger::processQueue, this);
    }

    ~AsyncLogger() {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            exitFlag = true;
        }
        condVar.notify_all();
        loggingThread.join();
    }

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(queueMutex);
        std::string msg = getCurrentDateTime() + " " + message;
        logQueue.push(msg);
        condVar.notify_all();
    }

private:
    std::string getCurrentDate() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        struct tm tm;
        localtime_s(&tm, &now_c);

        std::ostringstream oss;
        oss << (tm.tm_year + 1900) << "-"
            << (tm.tm_mon + 1) << "-"
            << tm.tm_mday;
        return oss.str();
    }

    std::string getCurrentDateTime() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        struct tm tm;
        localtime_s(&tm, &now_c);

        std::ostringstream oss;
        oss << (tm.tm_year + 1900) << "-"
            << (tm.tm_mon + 1) << "-"
            << tm.tm_mday << " "
            << tm.tm_hour << ":"
            << tm.tm_min << ":"
            << tm.tm_sec;
        return oss.str();
    }

    void processQueue() {
        while (true) {
            std::unique_lock<std::mutex> lock(queueMutex);
            condVar.wait(lock, [this]() { return !logQueue.empty() || exitFlag; });

            if (exitFlag && logQueue.empty()) break;

            std::string message = logQueue.front();
            logQueue.pop();
            lock.unlock();

            std::string currentDate = "log/" + getCurrentDate();
            std::ofstream logFile(currentDate + ".log", std::ios_base::app);
            logFile << message << std::endl;
        }
    }

    std::thread loggingThread;
    std::queue<std::string> logQueue;
    std::mutex queueMutex;
    std::condition_variable condVar;
    bool exitFlag;
};


AsyncLogger gAsyncLogger;