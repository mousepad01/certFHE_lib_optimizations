#include <thread>
#include <mutex>
#include <vector>
#include <condition_variable>
#include <functional>
#include <queue>

#include "Threadpool.h"

const int Threadpool::THR_CNT = std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 12;

Threadpool::Threadpool(): threads(THR_CNT){}

Threadpool * Threadpool::make_threadpool(){

    Threadpool * created = new Threadpool();

    for(int i = 0; i < THR_CNT; i++)
        created -> threads[i] = new std::thread(&Threadpool::wait_for_tasks, created);

    return created;
}

void Threadpool::wait_for_tasks(){

    while(true){

        std::function <void()> to_execute;
        
        {
            std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);

            this -> tasks_condition.wait(tasks_lock,
                                            [this]{
                                                return 
                                                !(this -> tasks.empty()) ||
                                                this -> closed;
                                            });

            if(this -> closed)
                return;
        
            to_execute = this -> tasks.front();
            this -> tasks.pop();
        }

        to_execute();
    }
}

// TODO: nr variabil de argumente
void Threadpool::add_task(std::function <void()> to_execute){

    {
        std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);
        this -> tasks.push(to_execute);
    }
    
    this -> tasks_condition.notify_one();
}

void Threadpool::close(){

    this -> closed = true;
    this -> tasks_condition.notify_all();

    for(int i = 0; i < THR_CNT; i++)
        this -> threads[i] -> join();
}


