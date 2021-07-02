#include <thread>
#include <mutex>
#include <vector>
#include <condition_variable>
#include <functional>
#include <queue>

class Threadpool{

    bool closed;

    std::vector <std::thread *> threads;
    std::queue <std::function <void ()>> tasks;

    std::mutex tasks_mutex;
    std::condition_variable tasks_condition;

    void wait_for_tasks();

    Threadpool();

public:

    static const int THR_CNT;

    static Threadpool * make_threadpool();
    
    // TODO: nr variabil de argumente
    void add_task(std::function <void()> to_execute);

    void close();
};


