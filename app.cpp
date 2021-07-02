#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <string>
#include <stdlib.h>

#include "certFHE.h"
#include "Threadpool.h"
using namespace certFHE;

class Timervar{

    uint64_t t;

public:

    void start_timer(){
        t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    uint64_t stop_timer(){

        uint64_t old_t = t;
        t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        
        return t - old_t;
    }
};

void test_time(const int test_count, const int FIRST_LEN = 100, const int SECOND_LEN = 79){

    Timervar t;

    for(int ts = 0; ts < test_count; ts++){

        t.start_timer();

        certFHE::Library::initializeLibrary();
        certFHE::Context context(1247,16);
        certFHE::SecretKey seckey(context);

        //std::cout << context.getDefaultN();

        std::cout << "after init context and key: " << t.stop_timer() << " miliseconds\n";

        Ciphertext ctxt1;

        for(int i = 0; i < FIRST_LEN; i++){
            
            Plaintext p(rand() % 2);
            Ciphertext c = seckey.encrypt(p);
            
            if(i == 0)
                ctxt1 = c;
            else
                ctxt1 += c;
        }

        Ciphertext ctxt2;

        for(int i = 0; i < 79; i++){
            
            Plaintext p(rand() % 2);
            Ciphertext c = seckey.encrypt(p);
            
            if(i == 0)
                ctxt2 = c;
            else
                ctxt2 += c;
        }

        std::cout << FIRST_LEN + SECOND_LEN << " adds time cost: " 
                    << t.stop_timer() << " miliseconds\n";

        ctxt1 *= ctxt2;
        std::cout << FIRST_LEN << " and " << SECOND_LEN << " multiplication time cost: " 
                    << t.stop_timer() << " miliseconds\n\n";

        ctxt1 *= ctxt2;
        std::cout << FIRST_LEN * SECOND_LEN << " and " << SECOND_LEN << " multiplication time cost: " 
                    << t.stop_timer() << " miliseconds\n\n";
    }
}

void testfct(){

    std::thread::id id = std::this_thread::get_id();

    for(int i = 0; i < 100; i++)
        std::cout << id << " " << i << '\n';
}

void test_threadpool(){

    Threadpool * thp = Threadpool::make_threadpool();

    for(int i = 0; i < 8; i++)
        thp -> add_task(&testfct);

    thp -> close();
}

int main(){

    srand(time(0));

    //test_time(10);

    test_threadpool();

    return 0;
}