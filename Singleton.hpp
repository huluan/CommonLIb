#ifndef TOM_COMMONLIB_SINGLETON_H_
#define TOM_COMMONLIB_SINGLETON_H_

namespace TomCommLib
{
template <typename T>
class Singleton
{
public:
	struct ObjectCreator
	{
		ObjectCreator() { Singleton<T>::instance(); }
		inline void DoNothing() const {}
	};

	static ObjectCreator objCreator;

	static T &instance()
	{
		static T obj;
		objCreator.DoNothing();
		return obj;
	}
};

template <typename T> typename Singleton<T>::ObjectCreator Singleton<T>::objCreator;
}

#endif
