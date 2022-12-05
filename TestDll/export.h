#pragma once

__declspec(dllexport) int GetNumber();

class __declspec(dllexport) fuck {
public:
	const char* funstr();
};

__declspec(dllexport) fuck GetFuck();