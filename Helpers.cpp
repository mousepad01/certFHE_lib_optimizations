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

 #pragma endregion