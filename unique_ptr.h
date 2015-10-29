#include <memory>
#include <iostream>

auto deleter = [](int *num){ std::cout << "delete" << std::endl;};
class A
{
    typedef std::unique_ptr<int, decltype(deleter)> IntPtr;
};
