#include <iostream>
#include <export.h>

static int number = 10;
static const char* str = "hello";

int main()
{
	static char* buf = new char[10];

	auto a = GetFuck();

	std::cout << str << std::endl;
	return 0;
}