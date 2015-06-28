#include "../CommonTools.hpp"
#include <iostream>

using namespace std;

int main()
{
	ifstream ifile("../ScopeGuard.hpp");
	if (!ifile.is_open())
	{
		cout << "failed to open file" <<endl;
	}
	cout << "file size is " << GetFileSize(ifile) << endl;
	return 0;
}
