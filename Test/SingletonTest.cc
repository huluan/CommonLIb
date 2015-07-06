#include "../Singleton.hpp"
#include <iostream>

using namespace std;
using namespace TomCommLib;

class SingletonTest
{
	friend class Singleton<SingletonTest>;

public:
	void DoSomeThing() { cout << "DoSomeThing" << endl; }
};

int main()
{
	Singleton<SingletonTest>::instance().DoSomeThing();
	return 0;
}
