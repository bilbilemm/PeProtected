#include <iostream>
#include "export.h"

static int number = 10;
static const char* str = "hello";

__declspec(dllexport) int GetNumber() {
	return number;
}

const char* fuck::funstr() {
	return str;
}

__declspec(dllexport) fuck GetFuck()
{
	return {};
}