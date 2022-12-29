#include <iostream>
#include <export.h>

static int number = 10;
static const char* str = "hello";

int main()
{
	static char* buf = new char[10];

	std::cin.get();
	auto a = GetFuck();

	std::cout << str << std::endl;
	return 0;
}