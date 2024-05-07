#include <stdexcept>

class cmsexcept: public std::exception {
private:
public:
    cmsexcept(char const* const _Message) : std::exception(_Message) {
    }
};
