#ifndef __CFG_H
#define __CFG_H

#include <string>
#include <vector>
class cfg {
    private:
        std::string protocol;
        std::string cmd;
        std::string url;
        std::string host;
        std::string conntection;
        std::string pragma;
        std::string cacheControl;
        std::string accept;
        std::string userAgent;
        std::string encoding;
        std::string language;
        std::vector<std::string> split(const std::string &s, char delim);
    public:
        void add(std::string s);
        void add(char *str) {
            add(std::string(str));
        }
}

#endif
