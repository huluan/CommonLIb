#include <memory>
#include <iostream>

void test(int **mem)
{
    std::cout << **mem << std::endl;
}

int main()
{
    std::shared_ptr<int> IntPtr(new int(10));
    test((int **)&IntPtr);
    return 0;
}
