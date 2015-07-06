#ifndef TOM_COMMONLIB_COMMONTOOLS_H_
#define TOM_COMMONLIB_COMMONTOOLS_H_
#include <fstream>

namespace TomCommLib
{
template <typename T>
size_t GetFileSize(T &file)
{
	file.seekg(0, std::ios::end);
	size_t fileSize = file.tellg();
	file.seekg(0, std::ios::beg);
	return fileSize;
}
}
#endif
