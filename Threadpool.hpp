#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <thread>
#include <mutex>
#include <vector>
#include <condition_variable>
#include <functional>
#include <queue>

template <typename T>
class Threadpool{

    bool closed;

    std::vector <std::thread *> threads;
    std::queue <std::function <void(T)>> tasks;
    std::queue <T> tasks_args;

    std::mutex tasks_mutex;
    std::condition_variable tasks_condition;

    void wait_for_tasks();

    Threadpool();

public:

    static const int THR_CNT;

    static Threadpool <T> * make_threadpool();
    
    void add_task(std::function <void(T)> to_execute, T to_execute_args);

    void close();
};

template <typename T>
const int Threadpool <T>::THR_CNT = std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 12;

template <typename T>
Threadpool <T>::Threadpool(): threads(THR_CNT){}

template <typename T>
Threadpool<T> * Threadpool <T>::make_threadpool(){

    Threadpool * created = new Threadpool();

    for(int i = 0; i < THR_CNT; i++)
        created -> threads[i] = new std::thread(&Threadpool<T>::wait_for_tasks, created);

    return created;
}

template <typename T>
void Threadpool <T>::wait_for_tasks(){

    while(true){

        std::function <void(T)> to_execute;
        T to_execute_args;
        
        {
            std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);

            this -> tasks_condition.wait(tasks_lock,
                                            [this]{
                                                return 
                                                !(this -> tasks.empty()) ||
                                                (this -> tasks.empty() && this -> closed);
                                            });

            if(this -> closed && this -> tasks.empty())
                return;
        
            to_execute = this -> tasks.front();
            this -> tasks.pop();

            to_execute_args = this -> tasks_args.front();
            this -> tasks_args.pop();
        }

        to_execute(to_execute_args);
    }
}

template <typename T>
void Threadpool <T>::add_task(std::function <void(T)> to_execute, T to_execute_args){

    {
        std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);

        this -> tasks.push(to_execute);
        this -> tasks_args.push(to_execute_args);
    }
    
    this -> tasks_condition.notify_one();
}

template <typename T>
void Threadpool <T>::close(){

    this -> closed = true;
    this -> tasks_condition.notify_all();

    for(int i = 0; i < THR_CNT; i++)
        this -> threads[i] -> join();
}

#endif


