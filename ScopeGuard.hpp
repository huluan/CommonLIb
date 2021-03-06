#ifndef TOM_COMMONLIB_SCOPE_GUARD_H_
#define TOM_COMMONLIB_SCOPE_GUARD_H_
#include <functional>
#define SCOPEGUARD_LINENAME_CAT(name, line) name##line
#define SCOPEGUARD_LINENAME(name, line) SCOPEGUARD_LINENAME_CAT(name, line)

// 因为有可能一个scope里面有好几个资源，所以我们使用EXIT加行号的方法来命名
#define ON_SCOPE_EXIT(callback) ScopeGuard SCOPEGUARD_LINENAME(EXIT, __LINE__)(callback)

namespace TomCommLib
{
class ScopeGuard
{
public:
	explicit ScopeGuard(std::function<void()> onExitScope)
		: onExitScope_(onExitScope), dismissed_(false) {}

	~ScopeGuard()
	{
		if (!dismissed_)
		{
			onExitScope_();
		}
	}

	void Dismiss()
	{
		dismissed_ = true;
	}

private:
	std::function<void()> onExitScope_;
	bool dismissed_;
private:
	ScopeGuard(ScopeGuard const &);
	ScopeGuard &operator=(ScopeGuard const &);
};
}
#endif
