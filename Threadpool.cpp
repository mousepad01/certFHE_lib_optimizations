#include <thread>
#include <mutex>
#include <vector>
#include <condition_variable>
#include <functional>
#include <queue>

class Threadpool{

    bool closed;

    std::vector <std::thread *> * threads;
    std::queue <std::function <void ()>> * tasks;

    std::mutex tasks_mutex;
    std::condition_variable tasks_condition;

    void wait_for_tasks(){

        while(true){
            
            {
                std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);

                this -> tasks_condition.wait(tasks_lock,
                                                [this]{
                                                    return 
                                                    !(this -> tasks -> empty()) ||
                                                    this -> closed;
                                                });
            }

            if(this -> closed)
                return;
            
            std::function <void()> to_execute = this -> tasks -> front();
            this -> tasks -> pop();

            to_execute();
        }
    }

public:

    static const int THR_CNT; 

    Threadpool(){

        closed = false;
        
        threads = new std::vector <std::thread>(THR_CNT);

        for(int i = 0; i < THR_CNT; i++)
            threads[i] = new std::thread(&Threadpool::wait_for_tasks, threads + i);
    }
    
    // TODO: nr variabil de argumente
    void add_task(std::function <void()> to_execute){

        {
            std::unique_lock <std::mutex> tasks_lock (this -> tasks_mutex);
            this -> tasks -> push(to_execute);
        }
        
        this -> tasks_condition.notify_one();
    }
    
};

const int Threadpool::THR_CNT = std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 12;