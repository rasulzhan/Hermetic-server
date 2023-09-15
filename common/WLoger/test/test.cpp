
#include "../Include/WLoger.h"

#include <iostream>

void temp() 
{
	WLI << "INFO";
	WLW << "WARNING";
	WLE << "EROR";
}
#include <thread>
int main()
{
	ATTACH_STRAEM(WL_ERROR, std::cout);
	ATTACH_STRAEM(WL_WARNING, std::cout);
	ATTACH_STRAEM(WL_INFO, std::cout);
	system("mkdir build");
	system("mkdir build\\log");

	GENERATE_LOG_FILE("build\\log");

	std::thread* ths[2];
	
	for (int i = 0; i < 2; i++)
	{
		ths[i] = new std::thread(temp);

	}
	for (int i = 0; i < 2; i++)
	{
		ths[i]->join();

	}
}