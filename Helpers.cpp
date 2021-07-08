#include "Helpers.h"

using namespace certFHE;

#pragma region Library class

void Library::initializeLibrary()
{
    //Introducing local time as seed for further pseudo random generator calls
	srand(time(NULL));
}

Threadpool <Args *> * Library::threadpool = NULL;

void Library::initializeLibrary(bool initPools)
{
	//Introducing local time as seed for further pseudo random generator calls
	srand(time(NULL));

	if (initPools == true) 
		Library::threadpool = Threadpool <Args *> ::make_threadpool();
}

Threadpool <Args *> * Library::getThreadpool() {

	if(Library::threadpool == NULL)
		Library::threadpool = Threadpool <Args *> ::make_threadpool();

	return Library::threadpool;
}

#pragma endregion 

#pragma region Helper class

bool Helper::exists(const uint64_t*v,const uint64_t len,const uint64_t value)
{
    for (int i = 0; i < len; i++)
		if (v[i] == value)
			return true;

	return false;

}

 void Helper::deletePointer(void* pointer, bool isArray)
 {
     if (pointer != NULL)
		if (isArray)
			delete[] pointer;
		else
			delete pointer;
 }

 void Helper::u64_chunk_cpy(Args * raw_args) {

	U64CpyArgs * args = (U64CpyArgs *)raw_args;

	const uint64_t * src = args->src;
	uint64_t * dest = args->dest;

	for (uint64_t i = args->fst_u64_pos; i < args->snd_u64_pos; i++)
		dest[i] = src[i];
		
	{
		std::lock_guard <std::mutex> lock(args->done_mutex);

		args->task_is_done = true;
		args->done.notify_all(); 
	}
}

 void Helper::u64_multithread_cpy(const uint64_t * src, uint64_t * dest, uint64_t to_cpy_len) {

	 Threadpool <Args *> * threadpool = Library::getThreadpool();
	 int thread_count = threadpool->THR_CNT;

	 uint64_t q;
	 uint64_t r;

	 int worker_cnt;

	 if (thread_count >= to_cpy_len) {

		 q = 1;
		 r = 0;

		 worker_cnt = to_cpy_len;
	 }
	 else {

		 q = to_cpy_len / thread_count;
		 r = to_cpy_len % thread_count;

		 worker_cnt = thread_count;
	 }

	 U64CpyArgs * args = new U64CpyArgs[worker_cnt];

	 int prevchnk = 0;

	 for (int thr = 0; thr < worker_cnt; thr++) {

		 args[thr].src = src;
		 args[thr].dest = dest;

		 args[thr].fst_u64_pos = prevchnk;
		 args[thr].snd_u64_pos = prevchnk + q;

		 if (r > 0) {

			 args[thr].snd_u64_pos += 1;
			 r -= 1;
		 }
		 prevchnk = args[thr].snd_u64_pos;

		 threadpool->add_task(&u64_chunk_cpy, args + thr);
	 }

	 for (int thr = 0; thr < worker_cnt; thr++) {

		 std::unique_lock <std::mutex> lock(args[thr].done_mutex);

		 args[thr].done.wait(lock, [thr, args] {
			 return args[thr].task_is_done;
		 });
	 }

	 delete[] args;
 }

 #pragma endregion